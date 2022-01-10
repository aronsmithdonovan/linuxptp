/**
 * @file msg.c
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <time.h>

#include "contain.h"
#include "msg.h"
#include "print.h"
#include "tlv.h"

#define VERSION_MASK 0x0f
#define VERSION      0x02

int assume_two_step = 0;
unsigned int message_counter = 0;

/*
 * Head room fits a VLAN Ethernet header, and 'msg' is 64 bit aligned.
 */
#define MSG_HEADROOM 24

struct message_storage {
	unsigned char reserved[MSG_HEADROOM];
	struct ptp_message msg;
} PACKED;

static TAILQ_HEAD(msg_pool, ptp_message) msg_pool = TAILQ_HEAD_INITIALIZER(msg_pool);

static struct {
	int total;
	int count;
} pool_stats;

#ifdef DEBUG_POOL
static void pool_debug(const char *str, void *addr)
{
	fprintf(stderr, "*** %p %10s total %d count %d used %d\n",
		addr, str, pool_stats.total, pool_stats.count,
		pool_stats.total - pool_stats.count);
}
#else
static void pool_debug(const char *str, void *addr)
{
}
#endif

static void announce_pre_send(struct announce_msg *m)
{
	m->currentUtcOffset = htons(m->currentUtcOffset);
	m->grandmasterClockQuality.offsetScaledLogVariance =
		htons(m->grandmasterClockQuality.offsetScaledLogVariance);
	m->stepsRemoved = htons(m->stepsRemoved);
}

static void announce_post_recv(struct announce_msg *m)
{
	m->currentUtcOffset = ntohs(m->currentUtcOffset);
	m->grandmasterClockQuality.offsetScaledLogVariance =
		ntohs(m->grandmasterClockQuality.offsetScaledLogVariance);
	m->stepsRemoved = ntohs(m->stepsRemoved);
}

// converts an unsigned 8-bit int to its binary representation
static void byte_to_bin(unsigned int n, char* bin)
{
	// static char bin[8] = {};
	// bin = (char*)malloc(8);
	int c, k;
	int i = 0;
	for (c=7; c>=0; c--) {
		k = n >> c;
		if (k & 1) { bin[i]='1'; }
		else { bin[i]='0'; }
		i++;
	}
	// return bin;
} 

// converts an unsigned 16-bit int to its binary representation
static void word_to_bin(unsigned int n, char* bin)
{
	// static char bin[16] = {};
	// bin = (char*)malloc(16);
	int c, k;
	int i = 0;
	for (c=15; c>=0; c--) {
		k = n >> c;
		if (k & 1) { bin[i]='1'; }
		else { bin[i]='0'; }
		i++;
	}
	// return bin;
} 

// converts an unsigned 32-bit int to its binary representation
static void dword_to_bin(unsigned int n, char* bin)
{
	// static char bin[32] = {};
	// bin = (char*)malloc(32);
	int c, k;
	int i = 0;
	for (c=31; c>=0; c--) {
		k = n >> c;
		if (k & 1) { bin[i]='1'; }
		else { bin[i]='0'; }
		i++;
	}
	// return bin;
} 

// prints header fields to a .txt file
static void print_headers_to_file(struct ptp_header *m, char filename[])
{
	// initialize
		char* bin;

	// initialization
		FILE *fp;
		fp = fopen(filename, "a");

	// print labels
		time_t now;
		time(&now);
		fprintf(fp, "%s\t%s\n", msg_type_string(m->tsmt & 0x0f), ctime(&now));

	// transportSpecific (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin(m->tsmt & 0xf0, bin);
		fprintf(fp, "\t[transportSpecific]\t%.4s\n", bin);
		free(bin);

	// reserved (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin(m->ver & 0xf0, bin);
		fprintf(fp, "\t[reserved0]\t\t%.4s\n", bin);
		free(bin);

	// versionPTP (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin((m->ver & 0x0f)<<4, bin);
		fprintf(fp, "\t[versionPTP]\t\t%.4s  (%u)\n", bin, m->ver & 0x0f);
		free(bin);

	// messageLength (UInteger16)
		bin = (char*)malloc(16);
		word_to_bin(m->messageLength, bin);
		fprintf(fp, "\t[messageLength]\t\t%.16s  (%u)\n", bin, m->messageLength);
		free(bin);
	
	// domainNumber (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin(m->domainNumber, bin);
		fprintf(fp, "\t[domainNumber]\t\t%.8s\n", bin);
		free(bin);
	
	// reserved1 (Octet)
		bin = (char*)malloc(8);
		byte_to_bin(m->reserved1, bin);
		fprintf(fp, "\t[reserved1]\t\t%.8s\n", bin);
		free(bin);
	
	// flagField[] (Octet)
		bin = (char*)malloc(8);
		byte_to_bin(m->flagField[0], bin);
		fprintf(fp, "\t[flagField1]\t\t%.8s\n", bin);
		free(bin);
		bin = (char*)malloc(8);
		byte_to_bin(m->flagField[1], bin);
		fprintf(fp, "\t[flagField2]\t\t%.8s\n", bin);
		free(bin);
	
	// correction (Integer64)
		fprintf(fp, "\t[correction]\t\t%ld\n", m->correction);
	
	// reserved2 (UInteger32)
		bin = (char*)malloc(32);
		dword_to_bin(m->reserved2, bin);
		fprintf(fp, "\t[reserved2]\t\t%.32s\n", bin);
		free(bin);
	
	// sequenceId (UInteger16)
		bin = (char*)malloc(16);
		word_to_bin(m->sequenceId, bin);
		fprintf(fp, "\t[sequenceId]\t\t%.16s  (%u)\n", bin, m->sequenceId);
		free(bin);
	
	// control (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin(m->control, bin);
		fprintf(fp, "\t[control]\t\t%.8s\n", bin);
		free(bin);
	
	// logMessageInterval (Integer8)
		fprintf(fp, "\t[logMessageInterval]\t%d\n", m->logMessageInterval);
	
	// dividing line
		fprintf(fp, "\n===============================================================\n\n");
	
	// close file
		fclose(fp);
}

// print header fields to terminal
static void print_headers_to_terminal(struct ptp_header *m, char qualifier[])
{
	// initialize
		char* bin;

	// print divider
		printf("\n====================================================\n");

	// print message type
		printf("%s:  %s\t", qualifier, msg_type_string(m->tsmt & 0x0f));

	// print machine timestamp
		time_t now;
		time(&now);
		printf("%s\n", ctime(&now));

	// transportSpecific (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin(m->tsmt & 0xf0, bin);
		printf("\t[transportSpecific]\t%.4s\n", bin);
		free(bin);

	// reserved (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin(m->ver & 0xf0, bin);
		printf("\t[reserved0]\t\t%.4s\n", bin);
		free(bin);

	//// versionPTP (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin((m->ver & 0x0f)<<4, bin);
		printf("\t[versionPTP]\t\t%.4s  (%u)\n", bin, m->ver & 0x0f);
		free(bin);

	//// messageLength (UInteger16)
		bin = (char*)malloc(16);
		word_to_bin(m->messageLength, bin);
		printf("\t[messageLength]\t\t%.16s  (%u)\n", bin, m->messageLength);
		free(bin);
	
	// domainNumber (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin(m->domainNumber, bin);
		printf("\t[domainNumber]\t\t%.8s\n", bin);
		free(bin);
	
	// reserved1 (Octet)
		bin = (char*)malloc(8);
		byte_to_bin(m->reserved1, bin);
		printf("\t[reserved1]\t\t%.8s\n", bin);
		free(bin);
	
	// flagField[] (Octet)
		bin = (char*)malloc(8);
		byte_to_bin(m->flagField[0], bin);
		printf("\t[flagField1]\t\t%.8s\n", bin);
		free(bin);
		bin = (char*)malloc(8);
		byte_to_bin(m->flagField[1], bin);
		printf("\t[flagField2]\t\t%.8s\n", bin);
		free(bin);
	
	//// correction (Integer64)
		printf("\t[correction]\t\t%ld\n", m->correction);
	
	// reserved2 (UInteger32)
		bin = (char*)malloc(32);
		dword_to_bin(m->reserved2, bin);
		printf("\t[reserved2]\t\t%.32s\n", bin);
		free(bin);
	
	//// sequenceId (UInteger16)
		bin = (char*)malloc(16);
		word_to_bin(m->sequenceId, bin);
		printf("\t[sequenceId]\t\t%.16s  (%u)\n", bin, m->sequenceId);
		free(bin);
	
	// control (UInteger8)
		bin = (char*)malloc(8);
		byte_to_bin(m->control, bin);
		printf("\t[control]\t\t%.8s\n", bin);
		free(bin);
	
	//// logMessageInterval (Integer8)
		printf("\t[logMessageInterval]\t%d\n", m->logMessageInterval);
	
	// dividing line
		printf("\n===============================================================\n\n");
}

// logs message
static void log_message(struct ptp_header *m)
{
	// initialization
		FILE *log;
		log = fopen("message-log.txt", "a");

	// log message
		time_t now;
		time(&now);
		fprintf(log, "%u\t%s\t%s", message_counter, msg_type_string(m->tsmt & 0x0f), ctime(&now));

	// close file
		message_counter++;
		fclose(log);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////// hdr_post_recv
///////////////////////////////////////////////////////////////////////////////////////////////////////////// uses ptp_header
static int hdr_post_recv(struct ptp_header *m)
{
	// DEBUG
	// fprintf(stderr, "[DEBUG]\tmsg.c\thdr_post_recv\n");

	// convert byte order
	if ((m->ver & VERSION_MASK) != VERSION)
		return -EPROTO;
	m->messageLength = ntohs(m->messageLength);  // converts UInteger16 messageLength from network byte order to host CPU byte order
	m->correction = net2host64(m->correction);  // converts Integer64 correction from network byte order to host CPU byte order
	m->sourcePortIdentity.portNumber = ntohs(m->sourcePortIdentity.portNumber);  // converts UInteger16 sourcePortIdentity.portNumber from network byte order to host CPU byte order
	m->sequenceId = ntohs(m->sequenceId);  // converts UInteger16 sequenceId from network byte order to host CPU byte order
	
	// print header fields to terminal
	// print_headers_to_terminal(m, "POST-RECEIVE");

	// print header fields to file
	print_headers_to_file(m, "post-receive.txt");

	// return
	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////// hdr_pre_send
///////////////////////////////////////////////////////////////////////////////////////////////////////////// uses ptp_header
static int hdr_pre_send(struct ptp_header *m)
{
	// DEBUG
	// fprintf(stderr, "[DEBUG]\tmsg.c\thdr_pre_send\n");

	// modify header values
	// reserved (nibble)
		m->ver = m->ver | 0xf0;
	// reserved1 (byte)
		m->reserved1 = 0xff;
	// flagField[0] (byte)
		m->flagField[0] = m->flagField[0] | 0xf8;
	// flagField[1] (byte)
		m->flagField[1] = m->flagField[1] | 0x80;
	// reserved2 (dword)
		m->reserved2 = 0xffffffff;
	// control (byte)
		m->control = 0xff;


	// print header fields to terminal
	// print_headers_to_terminal(m, "PRE-SEND");

	// print header fields to file
	print_headers_to_file(m, "pre-send.txt");

	// convert byte order
	m->messageLength = htons(m->messageLength);  // converts UInteger16 messageLength from host CPU byte order to network byte order
	m->correction = host2net64(m->correction);  // converts Integer64 correction from host CPU byte order to big endian byte order
	m->sourcePortIdentity.portNumber = htons(m->sourcePortIdentity.portNumber);  // converts UInteger16 sourcePortIdentity.portNumber from host CPU byte order to network byte order
	m->sequenceId = htons(m->sequenceId);  // converts UInteger16 sequenceId from from host CPU byte order to network byte order
	
	// log message
	log_message(m);

	// return
	return 0;
}

static uint8_t *msg_suffix(struct ptp_message *m)
{
	switch (msg_type(m)) {
	case SYNC:
		return NULL;
	case DELAY_REQ:
		return m->delay_req.suffix;
	case PDELAY_REQ:
		return NULL;
	case PDELAY_RESP:
		return NULL;
	case FOLLOW_UP:
		return m->follow_up.suffix;
	case DELAY_RESP:
		return m->delay_resp.suffix;
	case PDELAY_RESP_FOLLOW_UP:
		return m->pdelay_resp_fup.suffix;
	case ANNOUNCE:
		return m->announce.suffix;
	case SIGNALING:
		return m->signaling.suffix;
	case MANAGEMENT:
		return m->management.suffix;
	}
	return NULL;
}

static struct tlv_extra *msg_tlv_prepare(struct ptp_message *msg, int length)
{
	struct tlv_extra *extra, *tmp;
	uint8_t *ptr;

	/* Make sure this message type admits appended TLVs. */
	ptr = msg_suffix(msg);
	if (!ptr) {
		pr_err("TLV on %s not allowed", msg_type_string(msg_type(msg)));
		return NULL;
	}
	tmp = TAILQ_LAST(&msg->tlv_list, tlv_list);
	if (tmp) {
		ptr = (uint8_t *) tmp->tlv;
		ptr += sizeof(tmp->tlv->type);
		ptr += sizeof(tmp->tlv->length);
		ptr += tmp->tlv->length;
	}

	/* Check that the message buffer has enough room for the new TLV. */
	if ((unsigned long)(ptr + length) >
	    (unsigned long)(&msg->tail_room)) {
		pr_debug("cannot fit TLV of length %d into message", length);
		return NULL;
	}

	/* Allocate a TLV descriptor and setup the pointer. */
	extra = tlv_extra_alloc();
	if (!extra) {
		pr_err("failed to allocate TLV descriptor");
		return NULL;
	}
	extra->tlv = (struct TLV *) ptr;

	return extra;
}

static void msg_tlv_recycle(struct ptp_message *msg)
{
	struct tlv_extra *extra;

	while ((extra = TAILQ_FIRST(&msg->tlv_list)) != NULL) {
		TAILQ_REMOVE(&msg->tlv_list, extra, list);
		tlv_extra_recycle(extra);
	}
}

static void port_id_post_recv(struct PortIdentity *pid)
{
	pid->portNumber = ntohs(pid->portNumber);
}

static void port_id_pre_send(struct PortIdentity *pid)
{
	pid->portNumber = htons(pid->portNumber);
}

static int suffix_post_recv(struct ptp_message *msg, int len)
{
	uint8_t *ptr = msg_suffix(msg);
	struct tlv_extra *extra;
	int err;

	if (!ptr)
		return 0;

	while (len >= sizeof(struct TLV)) {
		extra = tlv_extra_alloc();
		if (!extra) {
			pr_err("failed to allocate TLV descriptor");
			return -ENOMEM;
		}
		extra->tlv = (struct TLV *) ptr;
		extra->tlv->type = ntohs(extra->tlv->type);
		extra->tlv->length = ntohs(extra->tlv->length);
		if (extra->tlv->length % 2) {
			tlv_extra_recycle(extra);
			return -EBADMSG;
		}
		len -= sizeof(struct TLV);
		ptr += sizeof(struct TLV);
		if (extra->tlv->length > len) {
			tlv_extra_recycle(extra);
			return -EBADMSG;
		}
		len -= extra->tlv->length;
		ptr += extra->tlv->length;
		err = tlv_post_recv(extra);
		if (err) {
			tlv_extra_recycle(extra);
			return err;
		}
		msg_tlv_attach(msg, extra);
	}
	return 0;
}

static void suffix_pre_send(struct ptp_message *msg)
{
	struct tlv_extra *extra;
	struct TLV *tlv;

	TAILQ_FOREACH(extra, &msg->tlv_list, list) {
		tlv = extra->tlv;
		tlv_pre_send(tlv, extra);
		tlv->type = htons(tlv->type);
		tlv->length = htons(tlv->length);
	}
	msg_tlv_recycle(msg);
}

static void timestamp_post_recv(struct ptp_message *m, struct Timestamp *ts)
{
	uint32_t lsb = ntohl(ts->seconds_lsb);
	uint16_t msb = ntohs(ts->seconds_msb);

	m->ts.pdu.sec  = ((uint64_t)lsb) | (((uint64_t)msb) << 32);
	m->ts.pdu.nsec = ntohl(ts->nanoseconds);
}

static void timestamp_pre_send(struct Timestamp *ts)
{
	ts->seconds_lsb = htonl(ts->seconds_lsb);
	ts->seconds_msb = htons(ts->seconds_msb);
	ts->nanoseconds = htonl(ts->nanoseconds);
}

/* public methods */

///////////////////////////////////////////////////////////////////////////////////////////////////////////// msg_allocate
struct ptp_message *msg_allocate(void)
{
	struct message_storage *s;
	struct ptp_message *m = TAILQ_FIRST(&msg_pool);

	if (m) {
		TAILQ_REMOVE(&msg_pool, m, list);
		pool_stats.count--;
		pool_debug("dequeue", m);
	} else {
		s = malloc(sizeof(*s));
		if (s) {
			m = &s->msg;
			pool_stats.total++;
			pool_debug("allocate", m);
		}
	}
	if (m) {
		memset(m, 0, sizeof(*m));
		m->refcnt = 1;
		TAILQ_INIT(&m->tlv_list);
	}

	return m;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////// msg_cleanup
void msg_cleanup(void)
{
	struct message_storage *s;
	struct ptp_message *m;

	tlv_extra_cleanup();

	while ((m = TAILQ_FIRST(&msg_pool)) != NULL) {
		TAILQ_REMOVE(&msg_pool, m, list);
		s = container_of(m, struct message_storage, msg);
		free(s);
	}
}

struct ptp_message *msg_duplicate(struct ptp_message *msg, int cnt)
{
	struct ptp_message *dup;
	int err;

	dup = msg_allocate();
	if (!dup) {
		return NULL;
	}
	memcpy(dup, msg, sizeof(*dup));
	dup->refcnt = 1;
	TAILQ_INIT(&dup->tlv_list);

	err = msg_post_recv(dup, cnt);
	if (err) {
		switch (err) {
		case -EBADMSG:
			pr_err("msg_duplicate: bad message");
			break;
		case -EPROTO:
			pr_debug("msg_duplicate: ignoring message");
			break;
		}
		msg_put(dup);
		return NULL;
	}
	if (msg_sots_missing(msg)) {
		pr_err("msg_duplicate: received %s without timestamp",
		       msg_type_string(msg_type(msg)));
		msg_put(dup);
		return NULL;
	}

	return dup;
}

void msg_get(struct ptp_message *m)
{
	m->refcnt++;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////// msg_post_recv
///////////////////////////////////////////////////////////////////////////////////////////////////////////// uses hdr_post_recv
int msg_post_recv(struct ptp_message *m, int cnt)
{
	// DEBUG
	// fprintf(stderr, "[DEBUG]\tmsg.c\tmsg_post_recv\n");

	int pdulen, type, err;

	if (cnt < sizeof(struct ptp_header))
		return -EBADMSG;

	err = hdr_post_recv(&m->header);
	if (err)
		return err;

	type = msg_type(m);

	switch (type) {
	case SYNC:
		pdulen = sizeof(struct sync_msg);
		break;
	case DELAY_REQ:
		pdulen = sizeof(struct delay_req_msg);
		break;
	case PDELAY_REQ:
		pdulen = sizeof(struct pdelay_req_msg);
		break;
	case PDELAY_RESP:
		pdulen = sizeof(struct pdelay_resp_msg);
		break;
	case FOLLOW_UP:
		pdulen = sizeof(struct follow_up_msg);
		break;
	case DELAY_RESP:
		pdulen = sizeof(struct delay_resp_msg);
		break;
	case PDELAY_RESP_FOLLOW_UP:
		pdulen = sizeof(struct pdelay_resp_fup_msg);
		break;
	case ANNOUNCE:
		pdulen = sizeof(struct announce_msg);
		break;
	case SIGNALING:
		pdulen = sizeof(struct signaling_msg);
		break;
	case MANAGEMENT:
		pdulen = sizeof(struct management_msg);
		break;
	default:
		return -EBADMSG;
	}

	if (cnt < pdulen)
		return -EBADMSG;

	switch (type) {
	case SYNC:
		timestamp_post_recv(m, &m->sync.originTimestamp);
		break;
	case DELAY_REQ:
		break;
	case PDELAY_REQ:
		break;
	case PDELAY_RESP:
		timestamp_post_recv(m, &m->pdelay_resp.requestReceiptTimestamp);
		port_id_post_recv(&m->pdelay_resp.requestingPortIdentity);
		break;
	case FOLLOW_UP:
		timestamp_post_recv(m, &m->follow_up.preciseOriginTimestamp);
		break;
	case DELAY_RESP:
		timestamp_post_recv(m, &m->delay_resp.receiveTimestamp);
		port_id_post_recv(&m->delay_resp.requestingPortIdentity);
		break;
	case PDELAY_RESP_FOLLOW_UP:
		timestamp_post_recv(m, &m->pdelay_resp_fup.responseOriginTimestamp);
		port_id_post_recv(&m->pdelay_resp_fup.requestingPortIdentity);
		break;
	case ANNOUNCE:
		clock_gettime(CLOCK_MONOTONIC, &m->ts.host);
		timestamp_post_recv(m, &m->announce.originTimestamp);
		announce_post_recv(&m->announce);
		break;
	case SIGNALING:
		port_id_post_recv(&m->signaling.targetPortIdentity);
		break;
	case MANAGEMENT:
		port_id_post_recv(&m->management.targetPortIdentity);
		break;
	}

	err = suffix_post_recv(m, cnt - pdulen);
	if (err)
		return err;

	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////// msg_pre_send
///////////////////////////////////////////////////////////////////////////////////////////////////////////// uses hdr_pre_send
int msg_pre_send(struct ptp_message *m)
{
	// DEBUG
	// fprintf(stderr, "[DEBUG]\tmsg.c\tmsg_pre_send\n");

	int type;

	if (hdr_pre_send(&m->header))
		return -1;

	type = msg_type(m);

	switch (type) {
	case SYNC:
		break;
	case DELAY_REQ:
		clock_gettime(CLOCK_MONOTONIC, &m->ts.host);
		break;
	case PDELAY_REQ:
		break;
	case PDELAY_RESP:
		timestamp_pre_send(&m->pdelay_resp.requestReceiptTimestamp);
		port_id_pre_send(&m->pdelay_resp.requestingPortIdentity);
		break;
	case FOLLOW_UP:
		timestamp_pre_send(&m->follow_up.preciseOriginTimestamp);
		break;
	case DELAY_RESP:
		timestamp_pre_send(&m->delay_resp.receiveTimestamp);
		m->delay_resp.requestingPortIdentity.portNumber =
			htons(m->delay_resp.requestingPortIdentity.portNumber);
		break;
	case PDELAY_RESP_FOLLOW_UP:
		timestamp_pre_send(&m->pdelay_resp_fup.responseOriginTimestamp);
		port_id_pre_send(&m->pdelay_resp_fup.requestingPortIdentity);
		break;
	case ANNOUNCE:
		announce_pre_send(&m->announce);
		break;
	case SIGNALING:
		port_id_pre_send(&m->signaling.targetPortIdentity);
		break;
	case MANAGEMENT:
		port_id_pre_send(&m->management.targetPortIdentity);
		break;
	default:
		return -1;
	}
	suffix_pre_send(m);
	return 0;
}

struct tlv_extra *msg_tlv_append(struct ptp_message *msg, int length)
{
	struct tlv_extra *extra;

	extra = msg_tlv_prepare(msg, length);
	if (extra) {
		msg->header.messageLength += length;
		msg_tlv_attach(msg, extra);
	}
	return extra;
}

void msg_tlv_attach(struct ptp_message *msg, struct tlv_extra *extra)
{
	TAILQ_INSERT_TAIL(&msg->tlv_list, extra, list);
}

int msg_tlv_count(struct ptp_message *msg)
{
	int count = 0;
	struct tlv_extra *extra;

	for (extra = TAILQ_FIRST(&msg->tlv_list);
			extra != NULL;
			extra = TAILQ_NEXT(extra, list))
		count++;

	return count;
}

const char *msg_type_string(int type)
{
	switch (type) {
	case SYNC:
		return "SYNC";
	case DELAY_REQ:
		return "DELAY_REQ";
	case PDELAY_REQ:
		return "PDELAY_REQ";
	case PDELAY_RESP:
		return "PDELAY_RESP";
	case FOLLOW_UP:
		return "FOLLOW_UP";
	case DELAY_RESP:
		return "DELAY_RESP";
	case PDELAY_RESP_FOLLOW_UP:
		return "PDELAY_RESP_FOLLOW_UP";
	case ANNOUNCE:
		return "ANNOUNCE";
	case SIGNALING:
		return "SIGNALING";
	case MANAGEMENT:
		return "MANAGEMENT";
	}
	return "unknown";
}

void msg_print(struct ptp_message *m, FILE *fp)
{
	fprintf(fp,
		"\t"
		"%-10s "
//		"versionPTP         0x%02X "
//		"messageLength      %hu "
//		"domainNumber       %u "
//		"reserved1          0x%02X "
//		"flagField          0x%02X%02X "
//		"correction         %lld "
//		"reserved2          %u "
//		"sourcePortIdentity ... "
		"sequenceId %4hu "
//		"control            %u "
//		"logMessageInterval %d "
		,
		msg_type_string(msg_type(m)),
//		m->header.ver,
//		m->header.messageLength,
//		m->header.domainNumber,
//		m->header.reserved1,
//		m->header.flagField[0],
//		m->header.flagField[1],
//		m->header.correction,
//		m->header.reserved2,
//		m->header.sourcePortIdentity,
		m->header.sequenceId
//		m->header.control,
//		m->header.logMessageInterval
		);
	fprintf(fp, "\n");
}

void msg_put(struct ptp_message *m)
{
	m->refcnt--;
	if (m->refcnt) {
		return;
	}
	pool_stats.count++;
	pool_debug("recycle", m);
	msg_tlv_recycle(m);
	TAILQ_INSERT_HEAD(&msg_pool, m, list);
}

int msg_sots_missing(struct ptp_message *m)
{
	int type = msg_type(m);
	switch (type) {
	case SYNC:
	case DELAY_REQ:
	case PDELAY_REQ:
	case PDELAY_RESP:
		break;
	case FOLLOW_UP:
	case DELAY_RESP:
	case PDELAY_RESP_FOLLOW_UP:
	case ANNOUNCE:
	case SIGNALING:
	case MANAGEMENT:
	default:
		return 0;
	}
	return msg_sots_valid(m) ? 0 : 1;
}
