/*
 * WPA Supplicant - Haiku event handling routines
 * Copyright (c) 2010, Axel Dörfler, axeld@pinc-software.de.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * This file can be used as a starting point for layer2 packet implementation.
 */

#include <Application.h>
#include <Looper.h>
#include <String.h>

#include <net_notifications.h>

#include <new>


class EventLooper : public BLooper {
public:
	EventLooper(void *context, void *driverData, const char *interfaceName,
		void (*callback)(void *, void *, int))
		:
		fContext(context),
		fDriverData(driverData),
		fInterfaceName(interfaceName),
		fCallback(callback),
		fQuitting(false)
	{
		start_watching_network(B_WATCH_NETWORK_WLAN_CHANGES, this);
	}

	virtual ~EventLooper()
	{
		fQuitting = true;
		stop_watching_network(this);
	}

protected:
	virtual void MessageReceived(BMessage *message)
	{
		if (message->what != B_NETWORK_MONITOR) {
			BLooper::MessageReceived(message);
			return;
		}

		if (fQuitting)
			return;

		BString interfaceName;
		if (message->FindString("interface", &interfaceName) != B_OK)
			return;

		if (fInterfaceName.FindFirst(interfaceName) < 0) {
			// The notification is for some other interface
			return;
		}

		message->AddPointer("callback", (void *)fCallback);
		message->AddPointer("context", fContext);
		message->AddPointer("data", fDriverData);
		be_app->PostMessage(message);
	}

private:
	void *fContext;
	void *fDriverData;
	BString fInterfaceName;
	void (*fCallback)(void *, void *, int);
	bool fQuitting;
};


extern "C" void
haiku_unregister_events(void *events)
{
	EventLooper *eventLooper = (EventLooper *)events;
	if (eventLooper->Lock())
		eventLooper->Quit();
}


extern "C" int
haiku_register_events(void *ctx, void *drv, const char *ifname, void **events,
	void (*callback)(void *ctx, void *drv, int opcode))
{
	EventLooper *eventLooper = new(std::nothrow) EventLooper(ctx, drv, ifname,
		callback);
	if (eventLooper == NULL)
		return B_NO_MEMORY;

	eventLooper->Run();

	*events = eventLooper;
	return 0;
}
