/*
 * WPA Supplicant / Haiku notification functions
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

extern "C" {
#include "utils/includes.h"
#include "utils/common.h"
#include "common/defs.h"
#include "../config.h"

#include "notify_haiku.h"
}

#include <Application.h>
#include <Message.h>


void
wpa_supplicant_haiku_notify_state_change(struct wpa_supplicant *wpa_s,
	enum wpa_states new_state, enum wpa_states old_state)
{
	BMessage message(kMsgSupplicantStateChanged);
	message.AddPointer("interface", wpa_s);
	message.AddInt32("oldState", old_state);
	message.AddInt32("newState", new_state);
	be_app->PostMessage(&message);
}
