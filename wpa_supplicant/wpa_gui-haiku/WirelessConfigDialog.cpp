/*
 * WPA Supplicant - Wireless Config Dialog
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

#include <Button.h>
#include <CheckBox.h>
#include <GridLayout.h>
#include <GridView.h>
#include <GroupLayout.h>
#include <GroupView.h>
#include <MenuField.h>
#include <MenuItem.h>
#include <NetworkDevice.h>
#include <PopUpMenu.h>
#include <SpaceLayoutItem.h>
#include <TextControl.h>
#include <Window.h>
#include <View.h>

#include <new>

static const uint32 kMessageCancel = 'btcl';
static const uint32 kMessageOk = 'btok';


class WirelessConfigView : public BView {
public:
	WirelessConfigView()
		:
		BView("WirelessConfigView", B_WILL_DRAW),
		fPassword(NULL)
	{
		SetViewColor(ui_color(B_PANEL_BACKGROUND_COLOR));

		BGroupLayout* rootLayout = new(std::nothrow) BGroupLayout(B_VERTICAL);
		if (rootLayout == NULL)
			return;

		SetLayout(rootLayout);

		BGridView* controls = new(std::nothrow) BGridView();
		if (controls == NULL)
			return;

		BGridLayout* layout = controls->GridLayout();

		float inset = ceilf(be_plain_font->Size() * 0.7);
		rootLayout->SetInsets(inset, inset, inset, inset);
		rootLayout->SetSpacing(inset);
		layout->SetSpacing(inset, inset);

		fNetworkName = new(std::nothrow) BTextControl("Network Name:", "",
			NULL);
		if (fNetworkName == NULL)
			return;

		int32 row = 0;
		layout->AddItem(fNetworkName->CreateLabelLayoutItem(), 0, row);
		layout->AddItem(fNetworkName->CreateTextViewLayoutItem(), 1, row++);

		BPopUpMenu* authMenu = new(std::nothrow) BPopUpMenu("authMode");
		if (authMenu == NULL)
			return;

		fAuthOpen = new(std::nothrow) BMenuItem("Open", NULL);
		authMenu->AddItem(fAuthOpen);
		fAuthWEP = new(std::nothrow) BMenuItem("WEP", NULL);
		authMenu->AddItem(fAuthWEP);
		fAuthWPA = new(std::nothrow) BMenuItem("WPA/WPA2", NULL);
		authMenu->AddItem(fAuthWPA);

		BMenuField* authMenuField = new(std::nothrow) BMenuField(
			"Authentication:", authMenu);
		if (authMenuField == NULL)
			return;

		layout->AddItem(authMenuField->CreateLabelLayoutItem(), 0, row);
		layout->AddItem(authMenuField->CreateMenuBarLayoutItem(), 1, row++);

		fPassword = new(std::nothrow) BTextControl("Password:", "", NULL);
		if (fPassword == NULL)
			return;

		BLayoutItem* layoutItem = fPassword->CreateTextViewLayoutItem();
		layoutItem->SetExplicitMinSize(BSize(fPassword->StringWidth(
				"0123456789012345678901234567890123456789") + inset,
			B_SIZE_UNSET));

		layout->AddItem(fPassword->CreateLabelLayoutItem(), 0, row);
		layout->AddItem(layoutItem, 1, row++);

		fPersist = new(std::nothrow) BCheckBox("Store this configuration");
		layout->AddItem(BSpaceLayoutItem::CreateGlue(), 0, row);
		layout->AddView(fPersist, 1, row++);

		BGroupView* buttons = new(std::nothrow) BGroupView(B_HORIZONTAL);
		if (buttons == NULL)
			return;

		fCancelButton = new(std::nothrow) BButton("Cancel",
			new BMessage(kMessageCancel));
		buttons->GroupLayout()->AddView(fCancelButton);

		buttons->GroupLayout()->AddItem(BSpaceLayoutItem::CreateGlue());

		fOkButton = new(std::nothrow) BButton("OK", new BMessage(kMessageOk));
		buttons->GroupLayout()->AddView(fOkButton);

		rootLayout->AddView(controls);
		rootLayout->AddView(buttons);
	}

	virtual void
	AttachedToWindow()
	{
		fCancelButton->SetTarget(Window());
		fOkButton->SetTarget(Window());
		fOkButton->MakeDefault(true);
		fPassword->MakeFocus(true);
	}

	void
	SetUp(const BMessage& message)
	{
		BString networkName;
		if (message.FindString("name", &networkName) == B_OK)
			fNetworkName->SetText(networkName);

		uint32 authMode;
		if (message.FindUInt32("authentication", &authMode) != B_OK)
			authMode = B_NETWORK_AUTHENTICATION_NONE;

		switch (authMode) {
			default:
			case B_NETWORK_AUTHENTICATION_NONE:
				fAuthOpen->SetMarked(true);
				break;
			case B_NETWORK_AUTHENTICATION_WEP:
				fAuthWEP->SetMarked(true);
				break;
			case B_NETWORK_AUTHENTICATION_WPA:
			case B_NETWORK_AUTHENTICATION_WPA2:
				fAuthWPA->SetMarked(true);
				break;
		}

		BString password;
		if (message.FindString("password", &password) == B_OK)
			fPassword->SetText(password);
	}

	void
	Complete(BMessage& message)
	{
		message.RemoveName("name");
		message.AddString("name", fNetworkName->Text());

		uint32 authMode = B_NETWORK_AUTHENTICATION_NONE;
		if (fAuthWEP->IsMarked())
			authMode = B_NETWORK_AUTHENTICATION_WEP;
		else if (fAuthWPA->IsMarked())
			authMode = B_NETWORK_AUTHENTICATION_WPA;

		message.RemoveName("authentication");
		message.AddUInt32("authentication", authMode);

		message.RemoveName("password");
		message.AddString("password", fPassword->Text());

		message.RemoveName("persistent");
		message.AddBool("persistent", fPersist->Value() != 0);
	}

private:
	BTextControl* fNetworkName;
	BMenuItem* fAuthOpen;
	BMenuItem* fAuthWEP;
	BMenuItem* fAuthWPA;
	BTextControl* fPassword;
	BCheckBox* fPersist;
	BButton* fCancelButton;
	BButton* fOkButton;
};


class WirelessConfigWindow : public BWindow {
public:
	WirelessConfigWindow(BRect frame)
		:
		BWindow(BRect(50, 50, 269, 302), "Connect Wireless Network",
			B_TITLED_WINDOW, B_NOT_RESIZABLE | B_ASYNCHRONOUS_CONTROLS
				| B_NOT_ZOOMABLE | B_AUTO_UPDATE_SIZE_LIMITS),
		fConfigView(NULL),
		fDoneSem(-1),
		fResult(B_ERROR)
	{
		fDoneSem = create_sem(0, "wireless config done");
		if (fDoneSem < 0)
			return;

		BLayout* layout = new(std::nothrow) BGroupLayout(B_HORIZONTAL);
		if (layout == NULL)
			return;

		SetLayout(layout);

		fConfigView = new(std::nothrow) WirelessConfigView();
		if (fConfigView == NULL)
			return;

		layout->AddView(fConfigView);
	}

	virtual
	~WirelessConfigWindow()
	{
		if (fDoneSem >= 0)
			delete_sem(fDoneSem);
	}

	virtual void
	DispatchMessage(BMessage* message, BHandler* handler)
	{
		int8 key;
		if (message->what == B_KEY_DOWN
			&& message->FindInt8("byte", 0, &key) == B_OK
			&& key == B_ESCAPE) {
			PostMessage(kMessageCancel);
		}

		BWindow::DispatchMessage(message, handler);
	}

	virtual void
	MessageReceived(BMessage* message)
	{
		switch (message->what) {
			case kMessageCancel:
			case kMessageOk:
				fResult = message->what == kMessageCancel ? B_CANCELED : B_OK;
				release_sem(fDoneSem);
				return;
		}

		BWindow::MessageReceived(message);
	}

	status_t
	WaitForDialog(BMessage& message)
	{
		
		fConfigView->SetUp(message);

		CenterOnScreen();
		Show();

		while (acquire_sem(fDoneSem) == B_INTERRUPTED);

		status_t result = fResult;
		fConfigView->Complete(message);

		LockLooper();
		Quit();
		return result;
	}

private:
	WirelessConfigView* fConfigView;
	sem_id fDoneSem;
	status_t fResult;
};


status_t
wireless_config_dialog(BMessage& message)
{
	WirelessConfigWindow* configWindow
		= new(std::nothrow) WirelessConfigWindow(BRect(100, 100, 200, 200));
	if (configWindow == NULL)
		return B_NO_MEMORY;

	return configWindow->WaitForDialog(message);
}
