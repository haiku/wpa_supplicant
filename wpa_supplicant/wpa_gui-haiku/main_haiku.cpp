/*
 * WPA Supplicant / Haiku entrypoint
 * Copyright (c) 2011, Michael Lotz <mmlr@mlotz.ch>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <Application.h>
#include <Catalog.h>
#include <KeyStore.h>
#include <Locker.h>
#include <MessageQueue.h>
#include <MessageRunner.h>
#include <NetworkDevice.h>
#include <NetworkRoster.h>
#include <ObjectList.h>
#include <String.h>

#include <private/shared/AutoDeleter.h>
#include <net_notifications.h>

#include "WirelessConfigDialog.h"
#include "WPASupplicant.h" // private header currently inside Haiku

#include <new>

extern "C" {
#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/defs.h"

#include "../config.h"
#include "../notify.h"
#include "notify_haiku.h"
#include "../wpa_supplicant_i.h"
}

extern "C" {
#include <net/if_types.h>
#include <net80211/ieee80211_ioctl.h>
#include <sys/sockio.h>
}


#undef B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "wpa_supplicant"


static const uint32 kMsgJoinTimeout = 'jnto';
static const char *kWPASupplicantKeyring = "wpa_supplicant";


typedef	bool (*StateChangeCallback)(const wpa_supplicant *interface,
	BMessage *message, void *data);


class StateChangeWatchingEntry {
public:
								StateChangeWatchingEntry(
									const wpa_supplicant *interface,
									StateChangeCallback callback,
									void *data);


		bool					MessageReceived(
									const wpa_supplicant *interface,
									BMessage *message);

private:
		const wpa_supplicant *	fInterface;
		StateChangeCallback		fCallback;
		void *					fData;
};


StateChangeWatchingEntry::StateChangeWatchingEntry(
	const wpa_supplicant *interface, StateChangeCallback callback, void *data)
	:
	fInterface(interface),
	fCallback(callback),
	fData(data)
{
}


bool
StateChangeWatchingEntry::MessageReceived(const wpa_supplicant *interface,
	BMessage *message)
{
	if (interface != fInterface)
		return false;

	return fCallback(interface, message, fData);
}


class WPASupplicantApp : public BApplication {
public:
								WPASupplicantApp();
virtual							~WPASupplicantApp();

		status_t				InitCheck();

virtual	void					ReadyToRun();
virtual	void					MessageReceived(BMessage *message);

		status_t				RunSupplicantInMainThread();

private:
static	int32					_SupplicantThread(void *data);
static	void					_EventLoopProcessEvents(int sock,
									void *eventLoopContext, void *data);

		status_t				_EnqueueAndNotify(BMessage *message);
		status_t				_NotifyEventLoop();

		bool					_CheckAskForConfig(BMessage *message);

		status_t				_JoinNetwork(BMessage *message);
		status_t				_LeaveNetwork(BMessage *message);

		status_t				_NotifyNetworkEvent(BMessage *message);

static	void					_SuccessfullyJoined(
									const wpa_supplicant *interface,
									const BMessage &joinRequest);
static	void					_FailedToJoin(const wpa_supplicant *interface,
									const BMessage &joinRequest);

static	bool					_InterfaceStateChangeCallback(
									const wpa_supplicant *interface,
									BMessage *message, void *data);

		status_t				_StartWatchingInterfaceChanges(
									const wpa_supplicant *interface,
									StateChangeCallback callback, void *data);
		void					_NotifyInterfaceStateChanged(BMessage *message);

static	void					_SendReplyIfNeeded(BMessage &message,
									status_t status);

		status_t				fInitStatus;
		thread_id				fSupplicantThread;
		BMessageQueue			fEventQueue;

		int						fNotifySockets[2];

		BObjectList<StateChangeWatchingEntry>
								fWatchingEntryList;
		BLocker					fWatchingEntryListLocker;

		wpa_global *			fWPAGlobal;
		wpa_params				fWPAParameters;
};


WPASupplicantApp::WPASupplicantApp()
	:
	BApplication(kWPASupplicantSignature),
	fInitStatus(B_NO_INIT),
	fSupplicantThread(-1),
	fWPAGlobal(NULL)
{
	fNotifySockets[0] = fNotifySockets[1] = -1;

	fInitStatus = BApplication::InitCheck();
	if (fInitStatus != B_OK)
		return;

	memset(&fWPAParameters, 0, sizeof(fWPAParameters));
	//fWPAParameters.wpa_debug_level = MSG_DEBUG;

	fWPAGlobal = wpa_supplicant_init(&fWPAParameters);
	if (fWPAGlobal == NULL) {
		fInitStatus = B_ERROR;
		return;
	}

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fNotifySockets) != 0) {
		fInitStatus = errno;
		return;
	}
}


WPASupplicantApp::~WPASupplicantApp()
{
	if (fWPAGlobal == NULL)
		return;

	wpa_supplicant_terminate_proc(fWPAGlobal);

	// Wake the event loop up so it'll process the quit request and exit.
	_NotifyEventLoop();

	int32 result;
	wait_for_thread(fSupplicantThread, &result);

	wpa_supplicant_deinit(fWPAGlobal);

	close(fNotifySockets[0]);
	close(fNotifySockets[1]);
}


status_t
WPASupplicantApp::InitCheck()
{
	return fInitStatus;
}


void
WPASupplicantApp::ReadyToRun()
{
	fSupplicantThread = spawn_thread(_SupplicantThread,
		"wpa_supplicant thread", B_NORMAL_PRIORITY, this);
	if (fSupplicantThread < 0 || resume_thread(fSupplicantThread))
		PostMessage(B_QUIT_REQUESTED);
}


void
WPASupplicantApp::MessageReceived(BMessage *message)
{
	switch (message->what) {
		case kMsgWPAJoinNetwork:
		{
			if (_CheckAskForConfig(message)) {
				status_t status = wireless_config_dialog(*message);
				if (status != B_OK) {
					_SendReplyIfNeeded(*message, status);
					return;
				}
			}

			_EnqueueAndNotify(DetachCurrentMessage());
				// The event processing code will send the reply.
			return;
		}

		case kMsgWPALeaveNetwork:
		{
			_EnqueueAndNotify(DetachCurrentMessage());
				// The event processing code will send the reply.
			return;
		}

		case B_NETWORK_MONITOR:
		{
			BMessage *copy = new BMessage();
			*copy = *message;
			_EnqueueAndNotify(copy);
			return;
		}

		case kMsgSupplicantStateChanged:
		case kMsgJoinTimeout:
		{
			_NotifyInterfaceStateChanged(message);
			return;
		}
	}

	BApplication::MessageReceived(message);
}


int32
WPASupplicantApp::_SupplicantThread(void *data)
{
	WPASupplicantApp *app = (WPASupplicantApp *)data;

	// Register our notify socket with the polling event loop.
	if (eloop_register_read_sock(app->fNotifySockets[0],
			_EventLoopProcessEvents, app->fWPAGlobal, app) != 0) {
		return B_ERROR;
	}

	wpa_supplicant_run(app->fWPAGlobal);

	eloop_unregister_read_sock(app->fNotifySockets[0]);

	// There are two reasons why the supplicant thread quit:
	// 1.	The event loop was terminated because of a signal or error and the
	//		application is still there and running.
	// 2.	The app has quit and stopped the event loop.
	//
	// In case of 2. we're done, but in case of 1. we need to quit the still
	// running application. We use the app messenger to reach the app if it is
	// still running. If it already quit the SendMessage() will simply fail.

	be_app_messenger.SendMessage(B_QUIT_REQUESTED);
	return B_OK;
}


status_t
WPASupplicantApp::_EnqueueAndNotify(BMessage *message)
{
	if (!fEventQueue.Lock())
		return B_ERROR;

	fEventQueue.AddMessage(message);
	fEventQueue.Unlock();

	return _NotifyEventLoop();
}


status_t
WPASupplicantApp::_NotifyEventLoop()
{
	// This will interrupt the event loop and cause the message queue to be
	// processed through the installed handler.
	uint8 byte = 0;
	ssize_t written = write(fNotifySockets[1], &byte, sizeof(byte));
	if (written < 0)
		return written;

	return written == sizeof(byte) ? B_OK : B_ERROR;
}


void
WPASupplicantApp::_EventLoopProcessEvents(int sock, void *eventLoopContext,
	void *data)
{
	// This function is called from the event loop only.

	WPASupplicantApp *app = (WPASupplicantApp *)data;

	uint8 bytes[25];
	read(app->fNotifySockets[0], bytes, sizeof(bytes));
		// discard them, they are just here to wake the event loop

	BMessageQueue &queue = app->fEventQueue;
	if (!queue.Lock())
		return;

	while (true) {
		BMessage *message = queue.FindMessage((int32)0);
		if (message == NULL)
			break;

		queue.RemoveMessage(message);

		bool needsReply = false;
		bool deleteMessage = true;
		status_t status = B_MESSAGE_NOT_UNDERSTOOD;
		switch (message->what) {
			case kMsgWPAJoinNetwork:
				status = app->_JoinNetwork(message);
				needsReply = status != B_OK;
				deleteMessage = needsReply;
				break;

			case kMsgWPALeaveNetwork:
				status = app->_LeaveNetwork(message);
				needsReply = status != B_OK;
				deleteMessage = needsReply;
				break;

			case B_NETWORK_MONITOR:
				app->_NotifyNetworkEvent(message);
				break;
		}

		if (needsReply)
			_SendReplyIfNeeded(*message, status);
		if (deleteMessage)
			delete message;
	}

	queue.Unlock();
}


bool
WPASupplicantApp::_CheckAskForConfig(BMessage *message)
{
	bool force = false;
	if (message->FindBool("forceDialog", &force) == B_OK && force)
		return true;

	if (!message->HasString("name"))
		return true;

	uint32 authMode = B_NETWORK_AUTHENTICATION_NONE;
	if (message->FindUInt32("authentication", &authMode) != B_OK)
		return true;

	if (authMode <= B_NETWORK_AUTHENTICATION_NONE
		|| message->HasString("password")) {
		return false;
	}

	// Try looking up the password in the keystore.
	const char *name = message->FindString("name");

	// TODO: Use the bssid as an optional secondary identifier to allow for
	// overlapping network names.
	BPasswordKey key;
	BKeyStore keyStore;
	if (keyStore.GetKey(kWPASupplicantKeyring, B_KEY_TYPE_PASSWORD,
			name, key) != B_OK) {
		return true;
	}

	message->AddString("password", key.Password());
	return false;
}


status_t
WPASupplicantApp::_JoinNetwork(BMessage *message)
{
	const char *interfaceName = NULL;
	status_t status = message->FindString("device", &interfaceName);
	if (status != B_OK)
		return status;

	// Check if we already registered this interface.
	wpa_supplicant *interface = wpa_supplicant_get_iface(fWPAGlobal,
		interfaceName);
	if (interface == NULL) {
		wpa_interface interfaceOptions;
		memset(&interfaceOptions, 0, sizeof(wpa_interface));

		interfaceOptions.ifname = interfaceName;

		interface = wpa_supplicant_add_iface(fWPAGlobal, &interfaceOptions,
			NULL);
	} else {
		// Disable everything
		wpa_supplicant_disable_network(interface, NULL);

		// Try to remove any existing network
		while (true) {
			wpa_ssid *network = wpa_config_get_network(interface->conf, 0);
			if (network == NULL)
				break;

			wpas_notify_network_removed(interface, network);
			wpa_config_remove_network(interface->conf, network->id);
		}
	}

	wpa_config* conf;
	CObjectDeleter<wpa_config, void, wpa_config_free> confDeleter;
	if (interface != NULL) {
		conf = interface->conf;
	} else {
		// We can continue without an interface and will try HAIKU_JOIN instead.
		conf = wpa_config_alloc_empty(NULL, NULL);
		confDeleter.SetTo(conf);
	}

	const char *networkName = NULL;
	status = message->FindString("name", &networkName);
	if (status != B_OK)
		return status;

	uint32 authMode = B_NETWORK_AUTHENTICATION_NONE;
	status = message->FindUInt32("authentication", &authMode);
	if (status != B_OK)
		return status;


	const char *username = NULL;
	uint32 encapsulationMode = B_NETWORK_EAP_ENCAPSULATION_NONE;
	if (authMode == B_NETWORK_AUTHENTICATION_EAP) {
		status = message->FindUInt32("encapsulation", &encapsulationMode);
		if (status != B_OK)
			return status;
			
		status = message->FindString("username", &username);
		if (status != B_OK)
			return status;
	}

	const char *password = NULL;
	if (authMode > B_NETWORK_AUTHENTICATION_NONE) {
		status = message->FindString("password", &password);
		if (status != B_OK)
			return status;
	}

	wpa_ssid *network = wpa_config_add_network(conf);
	if (network == NULL)
		return B_NO_MEMORY;

	if (interface != NULL)
		wpas_notify_network_added(interface, network);
	network->disabled = 1;
	wpa_config_set_network_defaults(network);

	// Fill in the info from the join request

	// The format includes the quotes
	BString value;
	value = "\"";
	value += networkName;
	value += "\"";
	int result = wpa_config_set(network, "ssid", value.String(), 0);

	if (result == 0)
		result = wpa_config_set(network, "scan_ssid", "1", 1);

	if (result == 0) {
		if (authMode == B_NETWORK_AUTHENTICATION_WPA || authMode == B_NETWORK_AUTHENTICATION_WPA2) {
			result = wpa_config_set(network, "key_mgmt", "WPA-PSK", 3);
		} else if (authMode == B_NETWORK_AUTHENTICATION_EAP) {
			result = wpa_config_set(network, "key_mgmt", "WPA-EAP", 3);
		} else {
			// B_NETWORK_AUTHENTICATION_NONE
			// B_NETWORK_AUTHENTICATION_WEP
			// Open or WEP.
			result = wpa_config_set(network, "key_mgmt", "NONE", 3);
		}
	}

	if (result == 0) {
		if (encapsulationMode == B_NETWORK_EAP_ENCAPSULATION_PEAP)
			result = wpa_config_set(network, "eap", "PEAP", 6);
			
		if (encapsulationMode == B_NETWORK_EAP_ENCAPSULATION_TLS)
			result = wpa_config_set(network, "eap", "TLS", 6);
	}

	if (result == 0) {
		if (authMode == B_NETWORK_AUTHENTICATION_WEP) {
			if (strncmp("0x", password, 2) == 0) {
				// interpret as hex key
				// TODO: make this non-ambiguous
				result = wpa_config_set(network, "wep_key0", password + 2, 7);
			} else {
				value = "\"";
				value += password;
				value += "\"";
				result = wpa_config_set(network, "wep_key0", value.String(), 8);
			}

			if (result == 0)
				result = wpa_config_set(network, "wep_tx_keyidx", "0", 9);
		} else if (authMode == B_NETWORK_AUTHENTICATION_WPA 
			|| authMode == B_NETWORK_AUTHENTICATION_WPA2) {
			// WPA/WPA2
			value = "\"";
			value += password;
			value += "\"";
			result = wpa_config_set(network, "psk", value.String(), 10);

			if (result == 0) {
				// We need to actually "apply" the PSK
				wpa_config_update_psk(network);
			}
		} else if (authMode == B_NETWORK_AUTHENTICATION_EAP) {
			value = "\"";
			value += password;
			value += "\"";
			result = wpa_config_set(network, "password", value.String(), 10);
			
			if (encapsulationMode != B_NETWORK_EAP_ENCAPSULATION_NONE) {
				value = "\"";
				value += username;
				value += "\"";
				result = wpa_config_set(network, "identity", value.String(), 11);
			}
		}

		if (result != 0) {
			// The key format is invalid, we need to ask for another password.
			BMessage newJoinRequest = *message;
			newJoinRequest.RemoveName("password");
			newJoinRequest.AddString("error",
				B_TRANSLATE("Password format invalid!"));
			newJoinRequest.AddBool("forceDialog", true);
			PostMessage(&newJoinRequest);
		}
	}

	if (result != 0) {
		if (interface != NULL)
			wpas_notify_network_removed(interface, network);
		wpa_config_remove_network(conf, network->id);
		return B_ERROR;
	}

	// Set up watching for the completion event
	_StartWatchingInterfaceChanges(interface, _InterfaceStateChangeCallback, message);

	if (interface == NULL) {
		// Attempt to connect using the Haiku extension ioctl
#ifndef IEEE80211_IOC_HAIKU_JOIN
#define IEEE80211_IOC_HAIKU_JOIN				0x6002
struct ieee80211_haiku_join_req {
	uint8 i_nwid[IEEE80211_NWID_LEN];
	uint8 i_nwid_len;

	uint32 i_authentication_mode;
	uint32 i_ciphers;
	uint32 i_group_ciphers;
	uint32 i_key_mode;

	uint32 i_key_len;
	uint8 i_key[];
};
#endif
		const size_t joinReqLen = sizeof(struct ieee80211_haiku_join_req) + PMK_LEN;
		struct ieee80211_haiku_join_req* joinReq =
			(struct ieee80211_haiku_join_req*)alloca(joinReqLen);
		joinReq->i_nwid_len = strlen(networkName);
		memcpy(joinReq->i_nwid, networkName, joinReq->i_nwid_len);
		joinReq->i_authentication_mode = authMode;
		joinReq->i_ciphers = 0;
		joinReq->i_group_ciphers = 0;
		joinReq->i_key_mode = 0;

		if (authMode >= B_NETWORK_AUTHENTICATION_WPA) {
			joinReq->i_key_len = PMK_LEN;
			memcpy(joinReq->i_key, network->psk, PMK_LEN);
		}

		BNetworkDevice device(interfaceName);
		struct ieee80211req request;
		request.i_type = IEEE80211_IOC_HAIKU_JOIN;
		request.i_data = joinReq;
		request.i_len = joinReqLen;
		result = device.Control(SIOCS80211, &request);
		printf("wpa_gui-haiku: used HAIKU_JOIN to join, status: %d\n", result);

		if (result != B_OK)
			return result;
	} else {
		// Otherwise, use wpa_supplicant to connect.
		wpa_supplicant_select_network(interface, network);
	}

	// Use a message runner to return a timeout and stop watching after a while
	BMessage timeout(kMsgJoinTimeout);
	timeout.AddPointer("interface", interface);

	BMessageRunner::StartSending(be_app_messenger, &timeout,
		15 * 1000 * 1000, 1);
		// Note that we don't need to cancel this. If joining works before the
		// timeout happens, it will take the StateChangeWatchingEntry with it
		// and the timeout message won't match anything and be discarded.

	return B_OK;
}


status_t
WPASupplicantApp::_LeaveNetwork(BMessage *message)
{
	const char *interfaceName = NULL;
	status_t status = message->FindString("device", &interfaceName);
	if (status != B_OK)
		return status;

	wpa_supplicant *interface = wpa_supplicant_get_iface(fWPAGlobal,
		interfaceName);
	if (interface == NULL) {
		// Attempt to leave directly.
		BNetworkDevice device(interfaceName);
		struct ieee80211req_mlme mlmeRequest;
		mlmeRequest.im_op = IEEE80211_MLME_DEAUTH;
		mlmeRequest.im_reason = IEEE80211_REASON_AUTH_LEAVE;
		struct ieee80211req request;
		request.i_type = IEEE80211_IOC_MLME;
		request.i_data = &mlmeRequest;
		request.i_len = sizeof(mlmeRequest);
		status = device.Control(SIOCS80211, &request);
		printf("wpa_gui-haiku: used to MLME to leave, status: %d\n", status);
		return status;
	}

	if (wpa_supplicant_remove_iface(fWPAGlobal, interface, 0) != 0)
		return B_ERROR;

	return B_OK;
}


status_t
WPASupplicantApp::_NotifyNetworkEvent(BMessage *message)
{
	// Verify that the interface is still there.
	BString interfaceName;
	if (message->FindString("interface", &interfaceName) != B_OK)
		return B_ERROR;
	interfaceName.Prepend("/dev/");

	void (*callback)(void *context, const char *ifname, int opcode) = NULL;
	status_t result = message->FindPointer("callback", (void **)&callback);
	if (result != B_OK)
		return result;

	void *context = NULL;
	result = message->FindPointer("context", &context);
	if (result != B_OK)
		return result;

	const int32 opcode = message->FindInt32("opcode");
	callback(context, interfaceName.String(), opcode);

	if (wpa_supplicant_get_iface(fWPAGlobal, interfaceName) == NULL) {
		// We likely joined via the HAIKU_JOIN ioctl. Generate a fake event.
		if (opcode == B_NETWORK_WLAN_JOINED)
			wpa_supplicant_haiku_notify_state_change(NULL, WPA_COMPLETED, WPA_AUTHENTICATING);
		else if (opcode == B_NETWORK_WLAN_LEFT)
			wpa_supplicant_haiku_notify_state_change(NULL, WPA_DISCONNECTED, WPA_AUTHENTICATING);
	}

	return B_OK;
}


void
WPASupplicantApp::_SuccessfullyJoined(const wpa_supplicant *interface,
	const BMessage &joinRequest)
{
	// We successfully connected with this configuration, store the config,
	// if requested, by adding a persistent network on the network device.
	if (!joinRequest.FindBool("persistent"))
		return;

	wireless_network network;
	memset(network.name, 0, sizeof(network.name));

	if (interface != NULL) {
		wpa_ssid *networkConfig = interface->current_ssid;
		if (networkConfig == NULL)
			return;

		memcpy(network.name, networkConfig->ssid,
			min_c(sizeof(network.name), networkConfig->ssid_len));
	} else {
		const char *interfaceName = NULL;
		status_t status = joinRequest.FindString("device", &interfaceName);
		if (status != B_OK)
			return;

		BNetworkDevice device(interfaceName);
		struct ieee80211req request;
		request.i_type = IEEE80211_IOC_SSID;
		request.i_data = network.name;
		request.i_len = sizeof(network.name);
		device.Control(SIOCG80211, &request);
	}

	//network.address.SetToLinkLevel((uint8 *)interface->bssid, ETH_ALEN);
		// TODO: Decide if we want to do this, it limits the network to
		// a specific base station instead of a "service set" that might
		// consist of more than one base station. On the other hand it makes
		// the network unique so the right one is connected in case of name
		// conflicts. It should probably be used as a hint, as in "preferred"
		// base station.

	if (joinRequest.FindUInt32("authentication",
			&network.authentication_mode) != B_OK) {
		return;
	}

	if (network.authentication_mode > B_NETWORK_AUTHENTICATION_NONE) {
		const char *password = NULL;
		if (joinRequest.FindString("password", &password) != B_OK)
			return;

		BString networkName(network.name, sizeof(network.name));
		BPasswordKey key(password, B_KEY_PURPOSE_NETWORK, networkName);

		BKeyStore keyStore;
		keyStore.AddKeyring(kWPASupplicantKeyring);
		keyStore.AddKey(kWPASupplicantKeyring, key);
	}

	if (interface == NULL)
		return;

	switch (interface->pairwise_cipher) {
		case WPA_CIPHER_NONE:
			network.cipher = B_NETWORK_CIPHER_NONE;
			break;
		case WPA_CIPHER_TKIP:
			network.cipher = B_NETWORK_CIPHER_TKIP;
			break;
		case WPA_CIPHER_CCMP:
			network.cipher = B_NETWORK_CIPHER_CCMP;
			break;
		default:
			fprintf(stderr, "WPASupplicantApp: Unknown pairwise cipher %d!",
				interface->pairwise_cipher);
			break;
	}

	switch (interface->group_cipher) {
		case WPA_CIPHER_NONE:
			network.group_cipher = B_NETWORK_CIPHER_NONE;
			break;
		case WPA_CIPHER_WEP40:
			network.group_cipher = B_NETWORK_CIPHER_WEP_40;
			break;
		case WPA_CIPHER_WEP104:
			network.group_cipher = B_NETWORK_CIPHER_WEP_104;
			break;
		case WPA_CIPHER_TKIP:
			network.group_cipher = B_NETWORK_CIPHER_TKIP;
			break;
		case WPA_CIPHER_CCMP:
			network.group_cipher = B_NETWORK_CIPHER_CCMP;
			break;
		default:
			fprintf(stderr, "WPASupplicantApp: Unknown group cipher %d!",
				interface->group_cipher);
			break;
	}

	switch (interface->key_mgmt) {
		case WPA_KEY_MGMT_IEEE8021X:
			network.key_mode = B_KEY_MODE_IEEE802_1X;
			break;
		case WPA_KEY_MGMT_PSK:
			network.key_mode = B_KEY_MODE_PSK;
			break;
		case WPA_KEY_MGMT_NONE:
			network.key_mode = B_KEY_MODE_NONE;
			break;
		case WPA_KEY_MGMT_FT_IEEE8021X:
			network.key_mode = B_KEY_MODE_FT_IEEE802_1X;
			break;
		case WPA_KEY_MGMT_FT_PSK:
			network.key_mode = B_KEY_MODE_FT_PSK;
			break;
		case WPA_KEY_MGMT_IEEE8021X_SHA256:
			network.key_mode = B_KEY_MODE_IEEE802_1X_SHA256;
			break;
		case WPA_KEY_MGMT_PSK_SHA256:
			network.key_mode = B_KEY_MODE_PSK_SHA256;
			break;
		default:
			fprintf(stderr, "WPASupplicantApp: Unknown key mode %d!",
				interface->key_mgmt);
			break;
	}

	BNetworkRoster::Default().AddPersistentNetwork(network);
}


void
WPASupplicantApp::_FailedToJoin(const wpa_supplicant *interface,
	const BMessage &joinRequest)
{
	BMessage leaveRequest = joinRequest;
	leaveRequest.what = kMsgWPALeaveNetwork;
	be_app->PostMessage(&leaveRequest);

	BMessage newJoinRequest = joinRequest;
	newJoinRequest.AddString("error",
		B_TRANSLATE("Failed to join network. (Incorrect password?)"));
	newJoinRequest.AddBool("forceDialog", true);
	be_app->PostMessage(&newJoinRequest);
}


bool
WPASupplicantApp::_InterfaceStateChangeCallback(const wpa_supplicant *interface,
	BMessage *message, void *data)
{
	// We wait for the completion state notification
	// TODO: We should also use the disconnect as an error case when joining,
	// but due to the event queue being serialized any disconnect happening
	// due to a new connect attempt would trigger that state. Either we need
	// to have the disconnect happen synchronously before joining again or
	// we need a way to discern one disconnect from the other, for example if
	// there was a way to tell from which network we disconnected.

	BMessage *originalMessage = (BMessage *)data;

	int32 newState;
	status_t result = B_ERROR;
	if (message->what == kMsgJoinTimeout) {
		_FailedToJoin(interface, *originalMessage);
		result = B_TIMED_OUT;
	} else if (message->FindInt32("newState", &newState) == B_OK) {
		switch (newState) {
			case WPA_COMPLETED:
			{
				if (originalMessage->what != kMsgWPAJoinNetwork)
					return false;

				_SuccessfullyJoined(interface, *originalMessage);
				result = B_OK;
				break;
			}

			case WPA_DISCONNECTED:
			{
				if (originalMessage->what != kMsgWPALeaveNetwork)
					return false;

				result = B_OK;
				break;
			}

			default:
				return false;
		}
	}

	_SendReplyIfNeeded(*originalMessage, result);
	delete originalMessage;
	return true;
}


status_t
WPASupplicantApp::_StartWatchingInterfaceChanges(
	const wpa_supplicant *interface, StateChangeCallback callback, void *data)
{
	StateChangeWatchingEntry *entry
		= new(std::nothrow) StateChangeWatchingEntry(interface, callback, data);
	if (entry == NULL)
		return B_NO_MEMORY;

	if (!fWatchingEntryListLocker.Lock()) {
		delete entry;
		return B_ERROR;
	}

	status_t result = B_OK;
	if (!fWatchingEntryList.AddItem(entry)) {
		result = B_ERROR;
		delete entry;
	}

	fWatchingEntryListLocker.Unlock();
	return result;
}


void
WPASupplicantApp::_NotifyInterfaceStateChanged(BMessage *message)
{
	const wpa_supplicant *interface;
	if (message->FindPointer("interface", (void **)&interface) != B_OK)
		return;

	if (!fWatchingEntryListLocker.Lock())
		return;

	for (int32 i = 0; i < fWatchingEntryList.CountItems(); i++) {
		StateChangeWatchingEntry *entry = fWatchingEntryList.ItemAt(i);
		if (entry->MessageReceived(interface, message)) {
			delete fWatchingEntryList.RemoveItemAt(i);
			i--;
		}
	}

	fWatchingEntryListLocker.Unlock();
}


void
WPASupplicantApp::_SendReplyIfNeeded(BMessage &message, status_t status)
{
	if (!message.IsSourceWaiting())
		return;

	BMessage reply;
	reply.AddInt32("status", status);
	message.SendReply(&reply);
}


int
main(int argc, char *argv[])
{
	WPASupplicantApp *app = new(std::nothrow) WPASupplicantApp();
	if (app == NULL)
		return B_NO_MEMORY;
	if (app->InitCheck() != B_OK)
		return app->InitCheck();

	app->Run();
	delete app;
	return 0;
}
