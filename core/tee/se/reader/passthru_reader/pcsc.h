/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef PCSC_H
#define PCSC_H

/* common control registers */
#define PCSC_REG_NUM_READERS    0x0
#define PCSC_REG_IRQ_STATUS     0x4
#define     PCSC_IRQ_STATE_CHANGE   0x1
#define PCSC_REG_MAX            0x8

/* per-reader control/status registers */
#define PCSC_REG_READER_CONTROL 0x0
/* preferred protocol, directly mapped to pcsclite */
#define     PCSC_READER_CTL_PROTOCOL_T0     0x0001
#define     PCSC_READER_CTL_PROTOCOL_T1     0x0002
#define     PCSC_READER_CTL_PROTOCOL_T15    0x0004
#define     PCSC_READER_CTL_PROTOCOL_RAW    0x0008
#define     PCSC_READER_CTL_PROTOCOL_MASK   0x000f
/* shared mode, directly mapped to pcsclite */
#define     PCSC_READER_CTL_SHARE_MASK      0x0030
#define     PCSC_READER_CTL_SHARE_SHIFT     4
#define     PCSC_READER_CTL_SHARE_EXCLUSIVE 0x0010
#define     PCSC_READER_CTL_SHARE_SHARED    0x0020
#define     PCSC_READER_CTL_SHARE_DIRECT    0x0030
/* disposition mode, directly mapped to pcsclite */
#define     PCSC_READER_CTL_DISPOSITION_MASK    0x0300
#define     PCSC_READER_CTL_DISPOSITION_SHIFT   8
#define     PCSC_READER_CTL_DISPOSITION_LEAVE_CARD  0x0000
#define     PCSC_READER_CTL_DISPOSITION_RESET_CARD  0x0100
#define     PCSC_READER_CTL_DISPOSITION_UNPOWER_CARD 0x0200
#define     PCSC_READER_CTL_DISPOSITION_EJECT_CARD  0x0300
/* reader commands */
#define     PCSC_READER_CTL_CONNECT         0x1000
#define     PCSC_READER_CTL_DISCONNECT      0x2000
#define     PCSC_READER_CTL_READ_ATR        0x4000
#define     PCSC_READER_CTL_TRANSMIT        0x8000
#define PCSC_REG_READER_STATE   0x4
/* reader state, directly mapped to pcsclite */
#define     PCSC_READER_STATE_IGNORE    0x0001
#define     PCSC_READER_STATE_CHANGED   0x0002
#define     PCSC_READER_STATE_UNKNOWN   0x0004
#define     PCSC_READER_STATE_UNAVAILABLE   0x0008
#define     PCSC_READER_STATE_EMPTY     0x0010
#define     PCSC_READER_STATE_PRESENT   0x0020
#define     PCSC_READER_STATE_ATRMATCH  0x0040
#define     PCSC_READER_STATE_EXCLUSIVE 0x0080
#define     PCSC_READER_STATE_INUSE     0x0100
#define     PCSC_READER_STATE_MUTE      0x0200
#define     PCSC_READER_STATE_UNPOWERED 0x0400
#define PCSC_REG_READER_TX_ADDR    0x8
#define PCSC_REG_READER_TX_SIZE    0xc
#define PCSC_REG_READER_RX_ADDR    0x10
#define PCSC_REG_READER_RX_SIZE    0x14
#define PCSC_REG_READER_ATR_LEN    0x18
#define PCSC_REG_READER_MAX     0x1c

#endif
