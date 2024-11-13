# Multiple BSSID and enhanced multi-BSS advertisements (EMA)
# Copyright (c) 2019, The Linux Foundation
# Copyright (c) 2022, Qualcomm Innovation Center, Inc
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os, subprocess, time, logging, tempfile
logger = logging.getLogger()

import hwsim_utils, hostapd
from wpasupplicant import WpaSupplicant
from utils import *

def mbssid_create_cfg_file(apdev, params, mbssid=1):
    hapd = hostapd.add_ap(apdev[0], {"ssid": "open"})
    status = hapd.get_driver_status()
    if "capa.mbssid_max_interfaces" not in status or \
       int(status["capa.mbssid_max_interfaces"]) < 8:
        raise HwsimSkip("MBSSID not supported")
    if mbssid == 2 and \
       ("capa.ema_max_periodicity" not in status or \
        int(status["capa.ema_max_periodicity"]) < 3):
        raise HwsimSkip("EMA not supported")
    hapd.disable()
    hglobal = hostapd.HostapdGlobal()
    hglobal.remove(apdev[0]['ifname'])

    # Create configuration file and add phy characteristics
    fd, fname = tempfile.mkstemp(dir='/tmp',
                                 prefix='hostapd-' + get_phy(apdev[0]))
    f = os.fdopen(fd, 'w')
    f.write("driver=nl80211\n")
    f.write("hw_mode=g\n")
    f.write("channel=1\n")
    f.write("ieee80211n=1\n")
    f.write("vht_oper_chwidth=0\n")
    f.write("ieee80211ac=1\n")
    f.write("he_oper_chwidth=0\n")
    f.write("ieee80211ax=1\n")
    f.write("mbssid=%d\n\n" % mbssid)

    if isinstance(apdev[0], dict):
        ifname = apdev[0]['ifname']
    else:
        ifname = apdev

    return (f, fname, ifname)

def mbssid_write_bss_params(f, ifname, idx, params=None, single_ssid=False):
    # Add BSS specific characteristics
    fields = ["wpa", "wpa_pairwise", "rsn_pairwise", "wpa_passphrase",
              "wpa_key_mgmt", "ieee80211w", "sae_pwe", "beacon_prot",
              "sae_password"]

    if idx == 0:
        f.write("interface=%s\n" % ifname)
    else:
        f.write("\nbss=%s\n" % (ifname + '-' + str(idx)))

    f.write("ctrl_interface=/var/run/hostapd\n")
    if single_ssid:
        f.write("ssid=single\n")
    else:
        f.write("ssid=bss-%s\n" % idx)
    f.write("bridge=br-lan\n")
    f.write("bssid=00:03:7f:12:2a:%02x\n" % idx)
    f.write("preamble=1\n")
    f.write("auth_algs=1\n")

    if params is None:
        return

    for field in fields:
        if field in params:
            f.write("%s=%s\n" % (field, params[field]))

def mbssid_dump_config(fname):
    with open(fname, 'r') as f:
        cfg = f.read()
        logger.debug("hostapd config:\n" + cfg)

def mbssid_stop_ap(hapd, pid):
    if "OK" not in hapd.request("TERMINATE"):
        raise Exception("Failed to terminate hostapd process")
    ev = hapd.wait_event(["CTRL-EVENT-TERMINATING"], timeout=15)
    if ev is None:
        raise Exception("CTRL-EVENT-TERMINATING not seen")
    for i in range(30):
        time.sleep(0.1)
        if not os.path.exists(pid):
            break
    if os.path.exists(pid):
        raise Exception("PID file exits after process termination")

def mbssid_start_ap(dev, apdev, params, fname, ifname, sta_params,
                    sta_params2=None, single_ssid=False, only_start_ap=False):
    pid = params['prefix'] + ".hostapd.pid"
    cmd = ['../../hostapd/hostapd', '-ddKtSB', '-P', pid, '-f',
           params['prefix'] + ".hostapd-log", fname]

    logger.info("Starting APs for " + ifname)
    res = subprocess.check_call(cmd)
    if res != 0:
        raise Exception("Could not start hostapd: %s" % str(res))

    # Wait for hostapd to complete initialization and daemonize.
    for i in range(10):
        if os.path.exists(pid):
            break
        time.sleep(0.2)
    if not os.path.exists(pid):
        # For now, assume MBSSID is not supported in the kernel.
        raise Exception("hostapd did not create PID file")

    hapd = hostapd.Hostapd(apdev[0]['ifname'])
    hapd.ping()
    os.remove(fname);

    # Allow enough time to pass for a Beacon frame to be captured.
    time.sleep(0.1)
    if only_start_ap:
        return hapd, pid

    ssid = "single" if single_ssid else "bss-0"
    dev[0].connect(ssid, **sta_params)
    sta = hapd.get_sta(dev[0].own_addr())
    if "[HE]" not in sta['flags']:
        raise Exception("Missing STA flag: HE")
    dev[0].request("DISCONNECT")

    if sta_params2:
        dev[0].wait_disconnected()
        ssid = "single" if single_ssid else "bss-1"
        dev[0].connect(ssid, **sta_params2)
        dev[0].request("DISCONNECT")

    mbssid_stop_ap(hapd, pid)

def test_he_ap_mbssid_open(dev, apdev, params):
    """HE AP MBSSID all open"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)
    for idx in range(0, 4):
        mbssid_write_bss_params(f, ifname, idx)
    f.close()

    try:
        sta_params = {"key_mgmt": "NONE", "scan_freq": "2412"}
        mbssid_start_ap(dev, apdev, params, fname, ifname, sta_params)
    finally:
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_mbssid_same_security(dev, apdev, params):
    """HE AP MBSSID all SAE"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)

    sae_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "sae_pwe": "1", "ieee80211w": "2"}

    for idx in range(0, 2):
        mbssid_write_bss_params(f, ifname, idx, sae_params)

    f.close()

    try:
        dev[0].set("sae_pwe", "1")
        dev[0].set("sae_groups", "")
        sta_params = {"psk": "12345678", "key_mgmt": "SAE", "ieee80211w": "2",
                      "pairwise": "CCMP", "group": "CCMP", "scan_freq": "2412"}
        mbssid_start_ap(dev, apdev, params, fname, ifname, sta_params)
    finally:
        dev[0].set("sae_pwe", "0")
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_mbssid_mixed_security1(dev, apdev, params):
    """HE AP MBSSID with mixed security (STA SAE)"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)

    psk_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "WPA-PSK"}

    owe_params = {"wpa": "2", "wpa_pairwise": "CCMP", "wpa_key_mgmt": "OWE"}

    sae_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "sae_pwe": "1", "ieee80211w": "2"}

    mbssid_write_bss_params(f, ifname, 0, sae_params)
    mbssid_write_bss_params(f, ifname, 1, psk_params)
    mbssid_write_bss_params(f, ifname, 2, owe_params)
    mbssid_write_bss_params(f, ifname, 3)
    mbssid_write_bss_params(f, ifname, 4, psk_params)
    mbssid_write_bss_params(f, ifname, 5, sae_params)
    mbssid_write_bss_params(f, ifname, 6, owe_params)
    mbssid_write_bss_params(f, ifname, 7)

    f.close()

    try:
        dev[0].set("sae_pwe", "1")
        dev[0].set("sae_groups", "")
        sta_params = {"psk": "12345678", "key_mgmt": "SAE", "ieee80211w": "2",
                      "pairwise": "CCMP", "group": "CCMP", "scan_freq": "2412"}
        mbssid_start_ap(dev, apdev, params, fname, ifname, sta_params)
    finally:
        dev[0].set("sae_pwe", "0")
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_mbssid_mixed_security2(dev, apdev, params):
    """HE AP MBSSID with mixed security (STA open)"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)

    psk_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "WPA-PSK"}

    owe_params = {"wpa": "2", "wpa_pairwise": "CCMP", "wpa_key_mgmt": "OWE"}

    sae_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "sae_pwe": "1", "ieee80211w": "2"}

    mbssid_write_bss_params(f, ifname, 0)
    mbssid_write_bss_params(f, ifname, 1, psk_params)
    mbssid_write_bss_params(f, ifname, 2, owe_params)
    mbssid_write_bss_params(f, ifname, 3, sae_params)
    mbssid_write_bss_params(f, ifname, 4)
    mbssid_write_bss_params(f, ifname, 5, psk_params)
    mbssid_write_bss_params(f, ifname, 6, sae_params)
    mbssid_write_bss_params(f, ifname, 7, owe_params)

    f.close()

    try:
        sta_params = {"key_mgmt": "NONE", "scan_freq": "2412"}
        mbssid_start_ap(dev, apdev, params, fname, ifname, sta_params)
    finally:
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_mbssid_mixed_security3(dev, apdev, params):
    """HE AP MBSSID with mixed security (WPA2-Personal + WPA3-Personal)"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)

    psk_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "WPA-PSK"}

    sae_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "sae_pwe": "1", "ieee80211w": "2"}

    mbssid_write_bss_params(f, ifname, 0, psk_params)
    mbssid_write_bss_params(f, ifname, 1, sae_params)

    f.close()

    try:
        dev[0].set("sae_pwe", "1")
        dev[0].set("sae_groups", "")
        sta_params = {"psk": "12345678", "key_mgmt": "WPA-PSK",
                      "pairwise": "CCMP", "group": "CCMP", "scan_freq": "2412"}
        sta_params2 = {"psk": "12345678", "key_mgmt": "SAE", "ieee80211w": "2",
                      "pairwise": "CCMP", "group": "CCMP", "scan_freq": "2412"}
        mbssid_start_ap(dev, apdev, params, fname, ifname, sta_params,
                        sta_params2)
    finally:
        dev[0].set("sae_pwe", "0")
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_mbssid_mixed_security4(dev, apdev, params):
    """HE AP MBSSID with mixed security (WPA2-Personal + WPA3-Personal+beacon prot)"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)

    psk_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "WPA-PSK"}

    sae_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "sae_pwe": "1", "ieee80211w": "2",
                  "beacon_prot": "1"}

    mbssid_write_bss_params(f, ifname, 0, psk_params)
    mbssid_write_bss_params(f, ifname, 1, sae_params)

    f.close()

    try:
        hapd, pid = mbssid_start_ap(dev, apdev, params, fname, ifname, None,
                                    only_start_ap=True)
        dev[0].set("sae_pwe", "1")
        dev[0].set("sae_groups", "")
        dev[0].connect("bss-1", psk="12345678", key_mgmt="SAE", ieee80211w="2",
                       beacon_prot="1", scan_freq="2412")
        dev[1].connect("bss-0", psk="12345678", key_mgmt="WPA-PSK",
                       scan_freq="2412")
        bssid0 = dev[0].get_status_field("bssid")
        bss0 = dev[0].get_bss(bssid0)
        ies0 = parse_ie(bss0['ie'])
        ext_cap0 = ies0[127]
        bssid1 = dev[1].get_status_field("bssid")
        bss1 = dev[0].get_bss(bssid1)
        ies1 = parse_ie(bss1['ie'])
        ext_cap1 = ies1[127]
        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        dev[0].wait_disconnected()
        dev[1].wait_disconnected()
        mbssid_stop_ap(hapd, pid)
        if not (ext_cap0[10] & 0x10):
            raise Exception("Beacon protection not enabled in non-TX BSS")
        if ext_cap1[10] & 0x10:
            raise Exception("Beacon protection enabled in TX BSS")
    finally:
        dev[0].set("sae_pwe", "0")
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_mbssid_single_ssid(dev, apdev, params):
    """HE AP MBSSID with mixed security and single SSID"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)

    psk_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "WPA-PSK"}

    sae_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "sae_pwe": "1", "ieee80211w": "2", "beacon_prot": "1"}

    mbssid_write_bss_params(f, ifname, 0, psk_params, single_ssid=True)
    mbssid_write_bss_params(f, ifname, 1, sae_params, single_ssid=True)

    f.close()

    try:
        dev[0].set("sae_pwe", "1")
        dev[0].set("sae_groups", "")
        sta_params = {"psk": "12345678", "key_mgmt": "WPA-PSK",
                      "pairwise": "CCMP", "group": "CCMP", "scan_freq": "2412"}
        sta_params2 = {"psk": "12345678", "key_mgmt": "SAE", "ieee80211w": "2",
                       "pairwise": "CCMP", "group": "CCMP", "scan_freq": "2412",
                       "beacon_prot": "1"}
        mbssid_start_ap(dev, apdev, params, fname, ifname, sta_params,
                        sta_params2, single_ssid=True)
    finally:
        dev[0].set("sae_pwe", "0")
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_mbssid_single_ssid_tm(dev, apdev, params):
    """HE AP MBSSID with mixed security and single SSID and transition mode"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)

    psk_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "WPA-PSK"}

    tm_params = {"wpa": "2", "wpa_passphrase": "12345678",
                 "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE WPA-PSK",
                 "sae_pwe": "2", "ieee80211w": "1", "beacon_prot": "1"}

    mbssid_write_bss_params(f, ifname, 0, psk_params, single_ssid=True)
    mbssid_write_bss_params(f, ifname, 1, tm_params, single_ssid=True)

    f.close()

    try:
        dev[0].set("sae_groups", "")
        hapd, pid = mbssid_start_ap(dev, apdev, params, fname, ifname, None,
                                    single_ssid=True, only_start_ap=True)
        dev[0].connect("single", psk="12345678", key_mgmt="SAE WPA-PSK",
                       ieee80211w="1", scan_freq="2412", beacon_prot="1")
        beacon_loss = False
        ev = dev[0].wait_event(["CTRL-EVENT-BEACON-LOSS"], timeout=5)
        if ev is not None:
            beacon_loss = True
        key_mgmt = dev[0].get_status_field("key_mgmt")
        mbssid_stop_ap(hapd, pid)
        if key_mgmt != "SAE":
            raise Exception("Did not use SAE")
    finally:
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_ema(dev, apdev, params):
    """HE EMA AP"""
    f, fname, ifname = mbssid_create_cfg_file(apdev, params, 2)

    sae_params = {"wpa": "2", "wpa_passphrase": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "sae_pwe": "1", "ieee80211w": "2"}

    for idx in range(0, 8):
        mbssid_write_bss_params(f, ifname, idx, sae_params)

    f.close()

    try:
        dev[0].set("sae_pwe", "1")
        dev[0].set("sae_groups", "")
        sta_params = {"psk": "12345678", "key_mgmt": "SAE", "ieee80211w": "2",
                      "pairwise": "CCMP", "group": "CCMP", "scan_freq": "2412"}
        mbssid_start_ap(dev, apdev, params, fname, ifname, sta_params)
    finally:
        dev[0].set("sae_pwe", "0")
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])

def test_he_ap_mbssid_beacon_prot(dev, apdev, params):
    """HE AP MBSSID beacon protection"""
    check_sae_capab(dev[0])
    check_sae_capab(dev[1])
    f, fname, ifname = mbssid_create_cfg_file(apdev, params)

    sae_params = {"wpa": "2", "sae_password": "12345678",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "ieee80211w": "2", "beacon_prot": "1"}
    mbssid_write_bss_params(f, ifname, 0, sae_params)
    sae_params = {"wpa": "2", "sae_password": "another password",
                  "wpa_pairwise": "CCMP", "wpa_key_mgmt": "SAE",
                  "ieee80211w": "2", "beacon_prot": "1"}
    mbssid_write_bss_params(f, ifname, 1, sae_params)

    f.close()
    mbssid_dump_config(fname)

    try:
        dev[0].set("sae_groups", "")
        dev[1].set("sae_groups", "")
        hapd, pid = mbssid_start_ap(dev, apdev, params, fname, ifname, None,
                                    only_start_ap=True)
        dev[0].connect("bss-0", psk="12345678", key_mgmt="SAE",
                       ieee80211w="2", beacon_prot="1", scan_freq="2412")
        dev[1].connect("bss-1", psk="another password", key_mgmt="SAE",
                       ieee80211w="2", beacon_prot="1", scan_freq="2412")

        beacon_loss0 = False
        beacon_loss1 = False
        ev = dev[1].wait_event(["CTRL-EVENT-BEACON-LOSS"], timeout=5)
        if ev is not None:
            beacon_loss1 = True
        ev = dev[0].wait_event(["CTRL-EVENT-BEACON-LOSS"], timeout=0.1)
        if ev is not None:
            beacon_loss0 = True

        mbssid_stop_ap(hapd, pid)

        if beacon_loss0 or beacon_loss1:
            raise Exception("Beacon loss detected")
    finally:
        subprocess.call(['ip', 'link', 'set', 'dev', apdev[0]['ifname'],
                         'address', apdev[0]['bssid']])
