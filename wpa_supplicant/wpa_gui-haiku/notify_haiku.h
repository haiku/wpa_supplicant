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

#ifndef NOTIFY_HAIKU_H
#define NOTIFY_HAIKU_H

static const uint32_t kMsgSupplicantStateChanged = 'stch';

struct wpa_supplicant;
enum wpa_states;

void wpa_supplicant_haiku_notify_state_change(struct wpa_supplicant *wpa_s,
	enum wpa_states new_state, enum wpa_states old_state);

#endif
