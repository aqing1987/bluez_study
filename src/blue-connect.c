/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <glib.h>
#include <getopt.h>
#include <signal.h>
#include "lib/uuid.h"
#include <btio/btio.h>
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "gatttool.h"

#include <lib/bluetooth.h>
#include <lib/hci.h>
#include <lib/hci_lib.h>
//typedef struct gatt_primary gatt_primary ;
static GIOChannel *iochannel = NULL;
static GAttrib *attrib = NULL;
static GMainLoop *event_loop = NULL;

static gchar *opt_src = NULL;
static gchar *opt_dst = NULL;
static gchar *opt_dst_type = NULL;
static gchar *opt_sec_level = NULL;
static const int opt_psm = 0;
static int opt_mtu = 0;
static int start;
static int end;

/*/////////////////////////////////////////////////////////////////////*/
#define LE_LINK		0x03

#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */

#define for_each_opt(opt, long, short) while ((opt=getopt_long(argc, argv, short ? short:"+", long, NULL)) != -1)

static volatile int signal_received = 0;
gboolean timeout_callback(gpointer data);
gboolean exit_lescan();
static int read_flags(uint8_t *flags, const uint8_t *data, size_t size)
{
	size_t offset;

	if (!flags || !data)
		return -EINVAL;

	offset = 0;
	while (offset < size) {
		uint8_t len = data[offset];
		uint8_t type;

		/* Check if it is the end of the significant part */
		if (len == 0)
			break;

		if (len + offset > size)
			break;

		type = data[offset + 1];

		if (type == FLAGS_AD_TYPE) {
			*flags = data[offset + 2];
			return 0;
		}

		offset += 1 + len;
	}

	return -ENOENT;
}

static int check_report_filter(uint8_t procedure, le_advertising_info *info)
{
	uint8_t flags;

	/* If no discovery procedure is set, all reports are treat as valid */
	if (procedure == 0)
		return 1;

	/* Read flags AD type value from the advertising report if it exists */
	if (read_flags(&flags, info->data, info->length))
		return 0;

	switch (procedure) {
	case 'l': /* Limited Discovery Procedure */
		if (flags & FLAGS_LIMITED_MODE_BIT)
			return 1;
		break;
	case 'g': /* General Discovery Procedure */
		if (flags & (FLAGS_LIMITED_MODE_BIT | FLAGS_GENERAL_MODE_BIT))
			return 1;
		break;
	default:
		fprintf(stderr, "Unknown discovery procedure\n");
	}

	return 0;
}
static void sigint_handler(int sig)
{
	signal_received = sig;
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'i' },
	{ 0, 0, 0, 0 }
};
static struct option lescan_options[] = {
	{ "help",	0, 0, 'h' },
	{ "privacy",	0, 0, 'p' },
	{ "passive",	0, 0, 'P' },
	{ "whitelist",	0, 0, 'w' },
	{ "discovery",	1, 0, 'd' },
	{ "duplicates",	0, 0, 'D' },
	{ 0, 0, 0, 0 }
};
static void helper_arg(int min_num_arg, int max_num_arg, int *argc,
			char ***argv, const char *usage)
{
	*argc -= optind;
	/* too many arguments, but when "max_num_arg < min_num_arg" then no
		 limiting (prefer "max_num_arg=-1" to gen infinity)
	*/
	if ( (*argc > max_num_arg) && (max_num_arg >= min_num_arg ) ) {
		fprintf(stderr, "%s: too many arguments (maximal: %i)\n",
				*argv[1], max_num_arg);
		printf("%s", usage);
		exit(1);
	}

	/* print usage */
	if (*argc < min_num_arg) {
		fprintf(stderr, "%s: too few arguments (minimal: %i)\n",
				*argv[1], min_num_arg);
		printf("%s", usage);
		exit(0);
	}

	*argv += optind;
}

static void eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
}

static int print_advertising_devices(int dd, uint8_t filter_type)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	struct sigaction sa;
	socklen_t olen;
	int len;
	int counter_cmp, counter =0;
	counter_cmp = 0;

	event_loop = g_main_loop_new(NULL,FALSE);
	
	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		printf("Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		printf("Could not set socket options\n");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);
	
//	g_timeout_add (100,exit_lescan,NULL);
	
	do{
		
		evt_le_meta_event *meta;
		le_advertising_info *info;
		char addr[18];
		
			counter ++;
			printf("counter : %d \n",counter);
		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EINTR && signal_received == SIGINT) {
				len = 0;
				goto done;
			}
			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto done;
			
		}
		
		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		meta = (void *) ptr;

		if (meta->subevent != 0x02)
			goto done;

		/* Ignoring multiple reports */
		info = (le_advertising_info *) (meta->data + 1);
		//counter_cmp = counter ;
		if (check_report_filter(filter_type, info)) {
			char name[30];

			memset(name, 0, sizeof(name));

			ba2str(&info->bdaddr, addr);
			eir_parse_name(info->data, info->length,
							name, sizeof(name) - 1);

			printf("%s %s\n", addr, name);

		}

		counter_cmp ++;
		printf("counter compare: %d \n",counter_cmp);
		
	} while(FALSE);
	
done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

	if (len < 0)
		return -1;

	return 0;
}

static const char *lescan_help =
	"Usage:\n"
	"\tlescan [--privacy] enable privacy\n"
	"\tlescan [--passive] set scan type passive (default active)\n"
	"\tlescan [--whitelist] scan for address in the whitelist only\n"
	"\tlescan [--discovery=g|l] enable general or limited discovery"
		"procedure\n"
	"\tlescan [--duplicates] don't filter duplicates\n";
	
gboolean exit_lescan()
{
    static int i = 0;
    
    i++;
    g_print("exit_lescan called %d times\n", i);
    if (10 == i)
    {
       // g_main_loop_quit( (GMainLoop*)data );
        exit (1);
    }
  
    return TRUE;
} 
static void cmd_lescan(int dev_id, int argc, char **argv)
{
	int err, opt, dd;
	uint8_t own_type = 0x00;
	uint8_t scan_type = 0x01;
	uint8_t filter_type = 0;
	uint8_t filter_policy = 0x00;
	uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
	uint8_t filter_dup = 1;

	for_each_opt(opt, lescan_options, NULL) {
		switch (opt) {
		case 'p':
			own_type = 0x01; /* Random */
			break;
		case 'P':
			scan_type = 0x00; /* Passive */
			break;
		case 'w':
			filter_policy = 0x01; /* Whitelist */
			break;
		case 'd':
			filter_type = optarg[0];
			if (filter_type != 'g' && filter_type != 'l') {
				fprintf(stderr, "Unknown discovery procedure\n");
				exit(1);
			}

			interval = htobs(0x0012);
			window = htobs(0x0012);
			break;
		case 'D':
			filter_dup = 0x00;
			break;
		default:
			printf("%s", lescan_help);
			return;
		}
	}
	helper_arg(0, 1, &argc, &argv, lescan_help);

	if (dev_id < 0)
		dev_id = hci_get_route(NULL);

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		exit(1);
	}

	err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
						own_type, filter_policy, 1000);
	if (err < 0) {
		perror("Set scan parameters failed");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 1000);
	if (err < 0) {
		perror("Enable scan failed");
		exit(1);
	}

	printf("LE Scan ...\n");
	
//	g_timeout_add(100,exit_lescan,NULL);
	
	err = print_advertising_devices(dd, filter_type);
		//printf("sending advistising.... \n");
	if (err < 0) {
		perror("Could not receive advertising events");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 1000);
	//printf("end lescan \n");
	if (err < 0) {
		perror("Disable scan failed");
		exit(1);
	}

	hci_close_dev(dd);
}
/*//////////////////////////////////////////////////////////////////////*/
struct characteristic_data {
	uint16_t orig_start;
	uint16_t start;
	uint16_t end;
	bt_uuid_t uuid;
};

static void cmd_help(int argcp, char **argvp);

static enum state {
	STATE_DISCONNECTED=0,
	STATE_CONNECTING=1,
	STATE_CONNECTED=2
} conn_state;


static const char 
  *tag_RESPONSE  = "respone",
  *tag_ERRCODE   = "code",
  *tag_HANDLE    = "handle",
  *tag_UUID      = "uuid",
  *tag_DATA      = "data",
  *tag_CONNSTATE = "state",
  *tag_SEC_LEVEL = "sec",
  *tag_MTU       = "mtu",
  *tag_DEVICE    = "dst",
  *tag_RANGE_START = "hstart",
  *tag_RANGE_END = "hend",
  *tag_PROPERTIES= "props",
  *tag_VALUE_HANDLE = "vhnd";

static const char
  *rsp_ERROR     = "error",
  *rsp_STATUS    = "status",
  *rsp_NOTIFY    = "ntfy",
  *rsp_IND       = "ind",
  *rsp_DISCOVERY = "find",
  *rsp_DESCRIPTORS = "desc",
  *rsp_READ      = "rd",
  *rsp_WRITE     = "wr";

static const char
  *err_CONN_FAIL = "connect fail",
  *err_COMM_ERR  = "com error",
  *err_PROTO_ERR = "protocol error",
  *err_NOT_FOUND = "notfound",
  *err_BAD_CMD   = "can not understand cmd",
  *err_BAD_PARAM = "do not understand parameter",
  *err_BAD_STATE = "bad state";

static const char 
  *st_DISCONNECTED = "disc",
  *st_CONNECTING   = "tryconn",
  *st_CONNECTED    = "conn";

static void resp_begin(const char *rsptype)
{
  printf(" %s:%s", tag_RESPONSE, rsptype);
}

static void send_sym(const char *tag, const char *val)
{
  printf(" %s:%s", tag, val);
}

static void send_uint(const char *tag, unsigned int val)
{
  printf(" %s=h%X", tag, val);
}

static void send_str(const char *tag, const char *val)
{
  //!!FIXME
  printf(" %s='%s", tag, val);
}

static void send_data(const unsigned char *val, size_t len)
{
  printf(" %s=b", tag_DATA);
  while ( len-- > 0 )
    printf("%02X", *val++);
}

static void resp_end()
{
  printf("\n");
  fflush(stdout);
}

static void resp_error(const char *errcode)
{
  resp_begin(rsp_ERROR);
  printf("\n");
  send_sym(tag_ERRCODE, errcode);
  printf("\n");
  resp_end();
}

static void cmd_status(int argcp, char **argvp)
{
  resp_begin(rsp_STATUS);
  switch(conn_state)
  {
    case STATE_CONNECTING:
      send_sym(tag_CONNSTATE, st_CONNECTING);
      send_str(tag_DEVICE, opt_dst);
      break;

    case STATE_CONNECTED:
      send_sym(tag_CONNSTATE, st_CONNECTED);
      send_str(tag_DEVICE, opt_dst);
      break;

    default:
      send_sym(tag_CONNSTATE, st_DISCONNECTED);
      break;
  }

  send_uint(tag_MTU, opt_mtu);
  send_str(tag_SEC_LEVEL, opt_sec_level);
  resp_end();
}

static void set_state(enum state st)
{
	conn_state = st;
        cmd_status(0, NULL);
}

static void events_handler(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t evt;
	uint16_t handle, olen;
	size_t plen;

	evt = pdu[0];

	if ( evt != ATT_OP_HANDLE_NOTIFY && evt != ATT_OP_HANDLE_IND )
	{
		printf("#Invalid opcode %02X in event handler??\n", evt);
		return;
	}

	assert( len >= 3 );
	handle = att_get_u16(&pdu[1]);

	resp_begin( evt==ATT_OP_HANDLE_NOTIFY ? rsp_NOTIFY : rsp_IND );
	send_uint( tag_HANDLE, handle );
	send_data( pdu+3, len-3 );
	resp_end();

	if (evt == ATT_OP_HANDLE_NOTIFY)
		return;

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_confirmation(opdu, plen);

	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_find_info_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t starting_handle, ending_handle, olen;
	size_t plen;

	assert( len == 5 );
	opcode = pdu[0];
	starting_handle = att_get_u16(&pdu[1]);
	ending_handle = att_get_u16(&pdu[3]);

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, starting_handle, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_find_by_type_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t starting_handle, ending_handle, att_type, olen;
	size_t plen;

	assert( len >= 7 );
	opcode = pdu[0];
	starting_handle = att_get_u16(&pdu[1]);
	ending_handle = att_get_u16(&pdu[3]);
	att_type = att_get_u16(&pdu[5]);

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, starting_handle, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_read_by_type_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t starting_handle, ending_handle, att_type, olen;
	size_t plen;

	assert( len == 7 || len == 21 );
	opcode = pdu[0];
	starting_handle = att_get_u16(&pdu[1]);
	ending_handle = att_get_u16(&pdu[3]);
	if (len == 7) {
		att_type = att_get_u16(&pdu[5]);
	}

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, starting_handle, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_read_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t handle, olen;
	size_t plen;

	assert( len == 3 );
	opcode = pdu[0];
	handle = att_get_u16(&pdu[1]);

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, handle, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_read_blob_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t handle, offset, olen;
	size_t plen;

	assert( len == 5 );
	opcode = pdu[0];
	handle = att_get_u16(&pdu[1]);
	offset = att_get_u16(&pdu[3]);

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, handle, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_read_multi_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t handle1, handle2, offset, olen;
	size_t plen;

	assert( len >= 5 );
	opcode = pdu[0];
	handle1 = att_get_u16(&pdu[1]);
	handle2 = att_get_u16(&pdu[3]);

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, handle1, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_read_by_group_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t starting_handle, ending_handle, att_group_type, olen;
	size_t plen;

	assert( len >= 7 );
	opcode = pdu[0];
	starting_handle = att_get_u16(&pdu[1]);
	ending_handle = att_get_u16(&pdu[3]);
	att_group_type = att_get_u16(&pdu[5]);

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, starting_handle, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_write_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t handle, olen;
	size_t plen;

	assert( len >= 3 );
	opcode = pdu[0];
	handle = att_get_u16(&pdu[1]);

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, handle, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_write_cmd(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t opcode;
	uint16_t handle;

	assert( len >= 3 );
	opcode = pdu[0];
	handle = att_get_u16(&pdu[1]);
}

static void gatts_signed_write_cmd(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t opcode;
	uint16_t handle;

	assert( len >= 15 );
	opcode = pdu[0];
	handle = att_get_u16(&pdu[1]);
}

static void gatts_prep_write_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode;
	uint16_t handle, offset, olen;
	size_t plen;

	assert( len >= 5 );
	opcode = pdu[0];
	handle = att_get_u16(&pdu[1]);
	offset = att_get_u16(&pdu[3]);

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, handle, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void gatts_exec_write_req(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	uint8_t *opdu;
	uint8_t opcode, flags;
	uint16_t olen;
	size_t plen;

	assert( len == 5 );
	opcode = pdu[0];
	flags = pdu[1];

	opdu = g_attrib_get_buffer(attrib, &plen);
	olen = enc_error_resp(opcode, 0, ATT_ECODE_REQ_NOT_SUPP, opdu, plen);
	if (olen > 0)
		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	if (err) {
		set_state(STATE_DISCONNECTED);
		resp_error(err_CONN_FAIL);
		printf("# Connect error: %s\n", err->message);
		return;
	}

	attrib = g_attrib_new(iochannel);
	g_attrib_register(attrib, ATT_OP_HANDLE_NOTIFY, GATTRIB_ALL_HANDLES,
						events_handler, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_HANDLE_IND, GATTRIB_ALL_HANDLES,
						events_handler, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_FIND_INFO_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_find_info_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_FIND_BY_TYPE_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_find_by_type_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_READ_BY_TYPE_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_read_by_type_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_READ_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_read_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_READ_BLOB_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_read_blob_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_READ_MULTI_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_read_multi_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_READ_BY_GROUP_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_read_by_group_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_WRITE_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_write_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_WRITE_CMD, GATTRIB_ALL_HANDLES,
	                  gatts_write_cmd, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_SIGNED_WRITE_CMD, GATTRIB_ALL_HANDLES,
	                  gatts_signed_write_cmd, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_PREP_WRITE_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_prep_write_req, attrib, NULL);
	g_attrib_register(attrib, ATT_OP_EXEC_WRITE_REQ, GATTRIB_ALL_HANDLES,
	                  gatts_exec_write_req, attrib, NULL);

	set_state(STATE_CONNECTED);
}

static void disconnect_io()
{
	if (conn_state == STATE_DISCONNECTED)
		return;

	g_attrib_unref(attrib);
	attrib = NULL;
	opt_mtu = 0;

	g_io_channel_shutdown(iochannel, FALSE, NULL);
	g_io_channel_unref(iochannel);
	iochannel = NULL;

	set_state(STATE_DISCONNECTED);
}

static void primary_all_cb(GSList *services, guint8 status, gpointer user_data)
{
	GSList *l;

	if (status) {
		resp_error(err_COMM_ERR); // Todo: status
		return;
	}

	resp_begin(rsp_DISCOVERY);
	for (l = services; l; l = l->next) {
		struct gatt_primary *prim = l->data;
		send_uint(tag_RANGE_START, prim->range.start);
                send_uint(tag_RANGE_END, prim->range.end);
                send_str(tag_UUID, prim->uuid);
	}
        resp_end();

}

static void primary_by_uuid_cb(GSList *ranges, guint8 status,
							gpointer user_data)
{
	GSList *l;

	if (status) {
		resp_error(err_COMM_ERR); // Todo: status
		return;
	}

	resp_begin(rsp_DISCOVERY);
	for (l = ranges; l; l = l->next) {
		struct att_range *range = l->data;
		send_uint(tag_RANGE_START, range->start);
                send_uint(tag_RANGE_END, range->end);
	}
        resp_end();
}

static void included_cb(GSList *includes, guint8 status, gpointer user_data)
{
	GSList *l;

	if (status) {
		resp_error(err_COMM_ERR); // Todo: status
		return;
	}

	resp_begin(rsp_DISCOVERY);
	for (l = includes; l; l = l->next) {
		struct gatt_included *incl = l->data;
                send_uint(tag_HANDLE, incl->handle);
                send_uint(tag_RANGE_START, incl->range.start);
                send_uint(tag_RANGE_END,   incl->range.end);
                send_str(tag_UUID, incl->uuid);
	}
        resp_end();
}

static void char_cb(GSList *characteristics, guint8 status, gpointer user_data)
{
	GSList *l;

	if (status) {
		resp_error(err_COMM_ERR); // Todo: status
		return;
	}

	resp_begin(rsp_DISCOVERY);
	for (l = characteristics; l; l = l->next) {
		struct gatt_char *chars = l->data;
                send_uint(tag_HANDLE, chars->handle);
                send_uint(tag_PROPERTIES, chars->properties);
                send_uint(tag_VALUE_HANDLE, chars->value_handle);
                send_str(tag_UUID, chars->uuid);
	}
        resp_end();
}

static void char_desc_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct att_data_list *list;
	guint8 format;
	uint16_t handle = 0xffff;
	int i;

	if (status != 0) {
		resp_error(err_COMM_ERR); // Todo: status
		return;
	}

	list = dec_find_info_resp(pdu, plen, &format);
	if (list == NULL) {
		resp_error(err_NOT_FOUND); // Todo: what does this mean?
		return;
	}

	resp_begin(rsp_DESCRIPTORS);
	for (i = 0; i < list->num; i++) {
		char uuidstr[MAX_LEN_UUID_STR];
		uint8_t *value;
		bt_uuid_t uuid;

		value = list->data[i];
		handle = att_get_u16(value);

		if (format == 0x01)
			uuid = att_get_uuid16(&value[2]);
		else
			uuid = att_get_uuid128(&value[2]);

		bt_uuid_to_string(&uuid, uuidstr, MAX_LEN_UUID_STR);
		send_uint(tag_HANDLE, handle);
                send_str (tag_UUID, uuidstr);
	}
        resp_end();

	att_data_list_free(list);

	if (handle != 0xffff && handle < end)
		gatt_find_info(attrib, handle + 1, end, char_desc_cb, NULL);
}

static void char_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	uint8_t value[plen];
	ssize_t vlen;

	if (status != 0) {
		resp_error(err_COMM_ERR); // Todo: status
		return;
	}

	vlen = dec_read_resp(pdu, plen, value, sizeof(value));
	if (vlen < 0) {
		resp_error(err_COMM_ERR);
		return;
	}

	resp_begin(rsp_READ);
        send_data(value, vlen);
        resp_end();
}

static void char_read_by_uuid_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct characteristic_data *char_data = user_data;
	struct att_data_list *list;
	int i;

	if (status == ATT_ECODE_ATTR_NOT_FOUND &&
				char_data->start != char_data->orig_start)
        {
		printf("# TODO case in char_read_by_uuid_cb\n");
		goto done;
        }

	if (status != 0) {
		resp_error(err_COMM_ERR); // Todo: status
		goto done;
	}

	list = dec_read_by_type_resp(pdu, plen);

	resp_begin(rsp_READ);
        if (list == NULL)
		goto nolist;

	for (i = 0; i < list->num; i++) {
		uint8_t *value = list->data[i];
		int j;

		char_data->start = att_get_u16(value) + 1;

		send_uint(tag_HANDLE, att_get_u16(value));
                send_data(value+2, list->len-2); // All the same length??
	}

	att_data_list_free(list);
nolist:
	resp_end();

done:
	g_free(char_data);
}

static void cmd_exit(int argcp, char **argvp)
{
	g_main_loop_quit(event_loop);
}

static gboolean channel_watcher(GIOChannel *chan, GIOCondition cond,
				gpointer user_data)
{
	disconnect_io();

	return FALSE;
}

static void cmd_connect(int argcp, char **argvp)
{
	printf("start to send cmd \n");
	if (conn_state != STATE_DISCONNECTED)
		return;

	if (argcp > 1) {
		g_free(opt_dst);
		opt_dst = g_strdup(argvp[2]);

		g_free(opt_dst_type);
		if (argcp > 5){
			opt_dst_type = g_strdup(argvp[2]);
			printf("%s \n",argvp[2]);}
		else
			opt_dst_type = g_strdup("public");
	}
	printf("check opt-dest \n");
	if (opt_dst == NULL) {
		resp_error(err_BAD_PARAM);
		printf("optdest errror \n");
		return;
	}

	set_state(STATE_CONNECTING);
	iochannel = gatt_connect(opt_src, opt_dst, opt_dst_type, opt_sec_level,
						opt_psm, opt_mtu, connect_cb);
	if (iochannel == NULL){
		set_state(STATE_DISCONNECTED);
		printf("io disconnected \n") ;}
	else
		g_io_add_watch(iochannel, G_IO_HUP, channel_watcher, NULL);
	printf("end send cmd \n");
}

static void cmd_disconnect(int argcp, char **argvp)
{
	disconnect_io();
}

static int strtohandle(const char *src)
{
	char *e;
	int dst;

	errno = 0;
	dst = strtoll(src, &e, 16);
	if (errno != 0 || *e != '\0')
		return -EINVAL;

	return dst;
}

static void char_write_req_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	if (status != 0) {
		resp_error(err_COMM_ERR); // Todo: status
		return;
	}

	if (!dec_write_resp(pdu, plen) && !dec_exec_write_resp(pdu, plen)) {
		resp_error(err_PROTO_ERR);
		return;
	}

        resp_begin(rsp_WRITE);
        resp_end();
}

static void cmd_char_write_common(int argcp, char **argvp, int with_response)
{
	uint8_t *value;
	size_t plen;
	int handle;

	if (conn_state != STATE_CONNECTED) {
		resp_error(err_BAD_STATE);
		return;
	}

	if (argcp < 5) {
		resp_error(err_BAD_PARAM);
		return;
	}
	if(argvp[4] == '\0')
	{ 
		printf("don't have parameter to send \n");
		return;
	}
	handle = strtohandle(argvp[4]);
	if (handle <= 0) {
		resp_error(err_BAD_PARAM);
		return;
	}

	plen = gatt_attr_data_from_string(argvp[5], &value);
	if (plen == 0) {
		resp_error(err_BAD_PARAM);
		return;
	}

	if (with_response)
		gatt_write_char(attrib, handle, value, plen,
					char_write_req_cb, NULL);
	else
        {
		gatt_write_char(attrib, handle, value, plen, NULL, NULL);
                resp_begin(rsp_WRITE);
                resp_end();
        }

	g_free(value);
}

static void cmd_char_write(int argcp, char **argvp)
{
  cmd_char_write_common(argcp, argvp, 0);
}

static void cmd_char_write_rsp(int argcp, char **argvp)
{
  cmd_char_write_common(argcp, argvp, 1);
}



static struct {
	const char *cmd;
	void (*func)(int argcp, char **argvp);
	const char *params;
	const char *desc;
} commands[] = {
	{ "help",		cmd_help,	"",
		"Show this help"},
	{ "lescan",		NULL,	"",
		"scan LE device using with root" },
	{ "quit",		cmd_exit,	"",
		"Exit interactive mode" },
//	{ "lescan" ,    cmd_lescan, "",
//		"Scan LE devices "	},
	{ "conn",		cmd_connect,	"[address [address type]]",
		"Connect to a remote device" },
	{ "disc",		cmd_disconnect,	"",
		"Disconnect from a remote device" },
	{ "wr",			cmd_char_write,	"<handle> <new value>",
		"Characteristic Value Write (No response)" },
	{ NULL, NULL, NULL}
};

static void cmd_help(int argcp, char **argvp)
{
	int i;

	for (i = 0; commands[i].cmd; i++)
		printf("-%-15s %-30s %s\n", commands[i].cmd,
				commands[i].params, commands[i].desc);
        cmd_status(0, NULL);
}

static void parse_line(char *line_read)
{
	gchar **argvp;
	int argcp;
	int i;

	line_read = g_strstrip(line_read);

	if (*line_read == '\0')
		goto done;

	g_shell_parse_argv(line_read, &argcp, &argvp, NULL);

	for (i = 0; commands[i].cmd; i++)
//	{	printf("%s",argvp[1]);
		if (strcasecmp(commands[i].cmd, argvp[0]) == 0)
			break;

	if (commands[i].cmd)
		commands[i].func(argcp, argvp);
	else
		resp_error(err_BAD_CMD);

	g_strfreev(argvp);

done:
	free(line_read);
}

static gboolean prompt_read(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	gchar *myline;
        GError *err;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

        if ( G_IO_STATUS_NORMAL != g_io_channel_read_line(chan, &myline, NULL, NULL, NULL)
             || myline == NULL
           )
        {
          printf("# Quitting on input read fail\n");
          g_main_loop_quit(event_loop);
          return FALSE;
        }

        parse_line(myline);
	return TRUE;
}

gboolean timeout_callback(gpointer data)
{
    static int i = 0;
    
    i++;
//    g_print("timeout_callback called %d times\n", i);
    if (5 == i)
    {
        g_main_loop_quit( (GMainLoop*)data );
        return FALSE;
    }
    if(i > 9)
    {
		exit(1);
	}

    return TRUE;
}


int main(int argc, char *argv[])
{
	GIOChannel *pchan;
	gint events;
	opt_sec_level = g_strdup("low");
	int dev_id = -1;
	
	opt_src = NULL;
	opt_dst = NULL;
	opt_dst_type = g_strdup("public");
	
	event_loop = g_main_loop_new(NULL, FALSE);
	pchan = g_io_channel_unix_new(fileno(stdin));
	g_io_channel_set_close_on_unref(pchan, TRUE);
	events = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
//	g_io_add_watch(pchan, events, prompt_read, NULL);

	int c;
	int i = 0;
           int digit_optind = 0;

           while (1) {
               int this_option_optind = optind ? optind : 1;
               int option_index = 0;
               static struct option long_options[] = {
                   {"help",  1, 0,  'h' },
                   {"LEscan",  1, 0,  's' },
                   {"quit",  1, 0,  'q' },
                   {"conn",  1, 0,  'c' },
				//   {"lescan",1 ,0,  's' },
                   {"wr",    1, 0,  'w' },
                   {0,  0,  0,  0 }
               };

               c = getopt_long(argc, argv, "hsqcdw",
                        long_options, &option_index);
               if (c == -1)
                   break;
               switch (c){
				   case 0:
				   break;
				   case 'h': 
					   printf("option 'help' %s \n",argv[1]);
					   commands[0].func(argc, argv);
					   break;
				   case 's':
					   printf("option lescan: \n");
					   cmd_lescan(dev_id,argc,argv);
					   	g_timeout_add(50,timeout_callback,event_loop);
						g_main_loop_run(event_loop);					
					   break;
				   case 'q':
						printf("option 'quit' \n");
						commands[2].func(argc, argv);
						exit(1);
						break;
					case 'c':
						printf("option connect \n");
						printf("opt_dest: %s \n",argv[2]);
						commands[3].func(argc, argv);
						g_timeout_add(50,timeout_callback,event_loop);
						g_main_loop_run(event_loop);					
						//break;
					case 'w':
						printf("option send command \n");
						printf("<handle> <value>: <%s> <%s> \n",argv[4],argv[5]);
						commands[5].func(argc, argv);
						g_timeout_add(50,timeout_callback,event_loop);
						g_main_loop_run(event_loop);
						break;
													
			   }
			   break;
				
    }


	cmd_disconnect(0, NULL);
		fflush(stdout);
	g_io_channel_unref(pchan);
	g_main_loop_unref(event_loop);
	
	
	g_free(opt_src);
	g_free(opt_dst);
	g_free(opt_sec_level);
	printf("check end \n");
 
	exit(EXIT_SUCCESS);
	//return EXIT_SUCCESS;
}

