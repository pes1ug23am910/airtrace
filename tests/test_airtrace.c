#include "airtrace.h"
#include "airtrace_pcap.h"
#include "unity.h"

#include <stdio.h>
#include <string.h>

static uint8_t bytes[2048];
static airtrace_frame frame;
static FILE *capture;

void setUp(void) { memset(bytes, 0, sizeof bytes); memset(&frame, 0, sizeof frame); }
void tearDown(void) { if (capture != NULL) { (void)fclose(capture); capture = NULL; } }

static void le16(uint8_t *p, uint16_t n) { p[0]=(uint8_t)n; p[1]=(uint8_t)(n>>8); }
static void le32(uint8_t *p, uint32_t n) { le16(p,(uint16_t)n); le16(p+2,(uint16_t)(n>>16)); }
static void be16(uint8_t *p, uint16_t n) { p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n; }
static void order32(uint8_t *p, uint32_t n, int big)
{
    unsigned i;
    for (i=0; i<4; ++i) p[big ? 3u-i : i]=(uint8_t)(n>>(i*8u));
}
static void order16(uint8_t *p, uint16_t n, int big)
{ if (big) be16(p,n); else le16(p,n); }

static size_t mac(uint8_t *p, uint16_t fc)
{
    size_t i;
    le16(p, fc); le16(p+2, 0x1234);
    for (i=0; i<18; ++i) p[4+i]=(uint8_t)(i+1);
    le16(p+22, 0x3210);
    return 24;
}
static size_t ie(uint8_t *p, uint8_t id, uint8_t size, const void *value)
{
    p[0]=id; p[1]=size;
    if (size != 0) memcpy(p+2,value,size);
    return 2u+size;
}
static size_t probe(void)
{
    const uint8_t name[]={ 'a', 'p' };
    return mac(bytes,0x0040)+ie(bytes+24,0,2,name);
}
static size_t eapol(uint8_t *p, uint16_t info)
{
    const uint8_t llc[]={0xaa,0xaa,3,0,0,0,0x88,0x8e};
    memcpy(p,llc,sizeof llc);
    p[8]=2; p[9]=3; be16(p+10,95); p[12]=2;
    be16(p+13,info); p[24]=7;
    return 8u+4u+95u;
}
static void ok_raw(size_t n)
{ TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_parse_frame(bytes,n,105,&frame)); }
static void ok_radio(size_t n)
{ TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_parse_frame(bytes,n,127,&frame)); }
static void fails_raw(size_t n)
{ TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,n,105,&frame)); }

static void test_null_input_output(void)
{
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_INVALID,airtrace_parse_frame(NULL,24,105,&frame));
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_INVALID,airtrace_parse_frame(bytes,24,105,NULL));
}
static void test_unknown_linktype(void)
{ TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_UNSUPPORTED,airtrace_parse_frame(bytes,24,1,&frame)); }
static void test_mac_truncation_every_prefix(void)
{
    size_t i; mac(bytes,0x0040);
    for (i=0;i<24;++i) fails_raw(i);
}
static void test_error_clears_output(void)
{
    size_t i; const uint8_t *p=(const uint8_t *)&frame;
    memset(&frame,0xff,sizeof frame); fails_raw(0);
    for (i=0;i<sizeof frame;++i) TEST_ASSERT_EQUAL_UINT8(0,p[i]);
}
static void test_mac_fields_and_flags(void)
{
    mac(bytes,0x4840); le16(bytes+22,0x3215); ok_raw(24);
    TEST_ASSERT_EQUAL_UINT16(0x1234,frame.duration);
    TEST_ASSERT_EQUAL_UINT8(0,frame.type); TEST_ASSERT_EQUAL_UINT8(4,frame.subtype);
    TEST_ASSERT_TRUE(frame.retry); TEST_ASSERT_TRUE(frame.protected_frame);
    TEST_ASSERT_EQUAL_UINT16(0x321,frame.seq); TEST_ASSERT_EQUAL_UINT8(5,frame.fragment);
    TEST_ASSERT_EQUAL_UINT16(0x3215,frame.sequence_control);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+4,frame.addrs[0],6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+10,frame.addrs[1],6);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+16,frame.addrs[2],6);
    TEST_ASSERT_TRUE(frame.has_bssid); TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+16,frame.bssid,6);
}
static void test_addr4_qos(void)
{
    size_t i; mac(bytes,0x0388);
    for (i=0;i<6;++i) bytes[24+i]=(uint8_t)(0xe0+i);
    le16(bytes+30,0x0007); ok_raw(32);
    TEST_ASSERT_EQUAL_UINT8(4,frame.addr_count); TEST_ASSERT_TRUE(frame.to_ds);
    TEST_ASSERT_TRUE(frame.from_ds); TEST_ASSERT_TRUE(frame.has_qos);
    TEST_ASSERT_EQUAL_UINT16(7,frame.qos_control); TEST_ASSERT_EQUAL_size_t(32,frame.header_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+24,frame.addrs[3],6); TEST_ASSERT_FALSE(frame.has_bssid);
}
static void test_addr4_truncated(void)
{ size_t i; mac(bytes,0x0308); for (i=24;i<30;++i) fails_raw(i); }
static void test_qos_truncated(void)
{ mac(bytes,0x0088); fails_raw(24); fails_raw(25); }
static void test_bssid_ds_mapping(void)
{
    mac(bytes,0x0108); ok_raw(24); TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+4,frame.bssid,6);
    mac(bytes,0x0208); ok_raw(24); TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+10,frame.bssid,6);
    mac(bytes,0x0008); ok_raw(24); TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+16,frame.bssid,6);
}
static void test_control_ack(void)
{
    mac(bytes,0x00d4); ok_raw(10); TEST_ASSERT_EQUAL_UINT8(1,frame.type);
    TEST_ASSERT_EQUAL_UINT8(1,frame.addr_count); TEST_ASSERT_FALSE(frame.has_seq);
    TEST_ASSERT_FALSE(frame.has_bssid); fails_raw(9);
}
static void test_bad_protocol_version(void)
{ mac(bytes,0x0041); fails_raw(24); }

static void test_assoc_request(void)
{
    mac(bytes,0x0000); le16(bytes+24,0x0431); le16(bytes+26,10); ok_raw(28);
    TEST_ASSERT_TRUE(frame.has_capability); TEST_ASSERT_EQUAL_UINT16(0x0431,frame.capability);
    TEST_ASSERT_TRUE(frame.has_listen_interval); TEST_ASSERT_EQUAL_UINT16(10,frame.listen_interval);
}
static void test_assoc_response(void)
{
    mac(bytes,0x0010); le16(bytes+24,0x0431); le16(bytes+26,17); le16(bytes+28,0xc123); ok_raw(30);
    TEST_ASSERT_TRUE(frame.has_capability); TEST_ASSERT_TRUE(frame.has_status);
    TEST_ASSERT_EQUAL_UINT16(17,frame.status_code); TEST_ASSERT_TRUE(frame.has_aid);
    TEST_ASSERT_EQUAL_UINT16(0x0123,frame.aid);
}
static void test_reassoc_request(void)
{
    const uint8_t ap[]={7,8,9,10,11,12};
    mac(bytes,0x0020); le16(bytes+24,0x0401); le16(bytes+26,20); memcpy(bytes+28,ap,6); ok_raw(34);
    TEST_ASSERT_TRUE(frame.has_current_ap); TEST_ASSERT_EQUAL_UINT8_ARRAY(ap,frame.current_ap,6);
    TEST_ASSERT_EQUAL_UINT16(20,frame.listen_interval);
}
static void test_reassoc_response(void)
{
    mac(bytes,0x0030); le16(bytes+24,0x0401); le16(bytes+26,30); le16(bytes+28,0xc008); ok_raw(30);
    TEST_ASSERT_TRUE(frame.has_status); TEST_ASSERT_EQUAL_UINT16(30,frame.status_code);
    TEST_ASSERT_EQUAL_UINT16(8,frame.aid);
}
static void test_probe_request(void)
{ ok_raw(probe()); TEST_ASSERT_TRUE(frame.has_ssid); TEST_ASSERT_EQUAL_UINT8_ARRAY("ap",frame.ssid,2); }
static void check_timestamp_frame(uint16_t fc)
{
    size_t i; mac(bytes,fc);
    for(i=0;i<8;++i) bytes[24+i]=(uint8_t)(i+1);
    le16(bytes+32,100); le16(bytes+34,0x431); ok_raw(36);
    TEST_ASSERT_TRUE(frame.has_timestamp); TEST_ASSERT_EQUAL_HEX64(UINT64_C(0x0807060504030201),frame.timestamp);
    TEST_ASSERT_TRUE(frame.has_beacon_interval); TEST_ASSERT_EQUAL_UINT16(100,frame.beacon_interval);
    TEST_ASSERT_EQUAL_UINT16(0x431,frame.capability);
}
static void test_probe_response(void) { check_timestamp_frame(0x0050); }
static void test_beacon(void) { check_timestamp_frame(0x0080); }
static void test_disassociation(void)
{ mac(bytes,0x00a0); le16(bytes+24,8); ok_raw(26); TEST_ASSERT_TRUE(frame.has_reason); TEST_ASSERT_EQUAL_UINT16(8,frame.reason_code); }
static void test_authentication(void)
{
    mac(bytes,0x00b0); le16(bytes+24,3); le16(bytes+26,2); le16(bytes+28,13); ok_raw(30);
    TEST_ASSERT_TRUE(frame.has_auth); TEST_ASSERT_EQUAL_UINT16(3,frame.auth_algorithm);
    TEST_ASSERT_EQUAL_UINT16(2,frame.auth_seq); TEST_ASSERT_EQUAL_UINT16(13,frame.status_code);
}
static void test_deauthentication(void)
{ mac(bytes,0x00c0); le16(bytes+24,7); ok_raw(26); TEST_ASSERT_TRUE(frame.has_reason); TEST_ASSERT_EQUAL_UINT16(7,frame.reason_code); }
static void test_management_fixed_truncation(void)
{
    const uint8_t subtypes[]={0,1,2,3,5,8,10,11,12};
    const size_t lengths[]={4,6,10,6,12,12,2,6,2};
    size_t i,j;
    for(i=0;i<sizeof subtypes;++i) {
        mac(bytes,(uint16_t)(subtypes[i]<<4));
        for(j=0;j<lengths[i];++j) fails_raw(24+j);
    }
}
static void test_supported_ies(void)
{
    uint8_t rates[]={0x82,0x84,0x8b,0x96}; uint8_t channel=11;
    uint8_t ht[26]={0}; uint8_t vht[12]={0}; uint8_t rsn[]={1,0}; size_t n=probe();
    ht[0]=0x6e; vht[0]=0x91;
    n+=ie(bytes+n,1,sizeof rates,rates); n+=ie(bytes+n,3,1,&channel);
    n+=ie(bytes+n,45,sizeof ht,ht); n+=ie(bytes+n,48,sizeof rsn,rsn); n+=ie(bytes+n,191,sizeof vht,vht);
    ok_raw(n); TEST_ASSERT_EQUAL_size_t(6,frame.ie_count);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(rates,frame.supported_rates,4); TEST_ASSERT_EQUAL_UINT8(4,frame.supported_rates_len);
    TEST_ASSERT_TRUE(frame.has_ds_channel); TEST_ASSERT_EQUAL_UINT16(11,frame.channel);
    TEST_ASSERT_TRUE(frame.has_ht_cap); TEST_ASSERT_TRUE(frame.has_rsn); TEST_ASSERT_TRUE(frame.has_vht_cap);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ht,frame.ht_cap,26); TEST_ASSERT_EQUAL_UINT8_ARRAY(vht,frame.vht_cap,12);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(rsn,bytes+frame.rsn_offset,2);
    TEST_ASSERT_EQUAL_UINT8(0,frame.ies[0].id); TEST_ASSERT_EQUAL_UINT8(2,frame.ies[0].len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("ap",bytes+frame.ies[0].offset,2);
}
static void test_hidden_and_binary_ssids(void)
{
    const uint8_t ssid[]={0,'x',0xff}; mac(bytes,0x0040); ie(bytes+24,0,0,NULL); ok_raw(26);
    TEST_ASSERT_TRUE(frame.has_ssid); TEST_ASSERT_EQUAL_UINT8(0,frame.ssid_len);
    ie(bytes+24,0,sizeof ssid,ssid); ok_raw(29); TEST_ASSERT_EQUAL_UINT8_ARRAY(ssid,frame.ssid,3);
}
static void test_maximum_ssid(void)
{ uint8_t ssid[32]; memset(ssid,'a',sizeof ssid); mac(bytes,0x0040); ie(bytes+24,0,32,ssid); ok_raw(58); TEST_ASSERT_EQUAL_UINT8(32,frame.ssid_len); }
static void test_truncated_ie_header(void)
{ size_t n=probe(); bytes[n]=45; fails_raw(n+1); }
static void test_truncated_ie_payload(void)
{ size_t n=probe(); bytes[n]=45; bytes[n+1]=26; fails_raw(n+2); fails_raw(n+27); }
static void test_invalid_known_ie_lengths(void)
{
    const uint8_t ids[]={0,1,1,3,3,45,48,191}; const uint8_t lengths[]={33,0,9,0,2,25,1,11}; size_t i;
    for(i=0;i<sizeof ids;++i) { mac(bytes,0x0040); bytes[24]=ids[i]; bytes[25]=lengths[i]; fails_raw(26u+lengths[i]); }
}
static void test_unknown_ie_skipped(void)
{ const uint8_t v[]={1,2,3,4,5}; size_t n=probe(); n+=ie(bytes+n,200,sizeof v,v); ok_raw(n); TEST_ASSERT_EQUAL_size_t(2,frame.ie_count); }
static void test_ie_table_capacity(void)
{
    size_t i,n=mac(bytes,0x0040);
    for(i=0;i<AIRTRACE_MAX_IES;++i) n+=ie(bytes+n,200,0,NULL);
    ok_raw(n); TEST_ASSERT_EQUAL_size_t(AIRTRACE_MAX_IES,frame.ie_count);
    n+=ie(bytes+n,200,0,NULL);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_CAPACITY,airtrace_parse_frame(bytes,n,105,&frame));
}

static void test_radiotap_empty(void)
{ le16(bytes+2,8); mac(bytes+8,0x0040); ok_radio(32); TEST_ASSERT_EQUAL_UINT16(8,frame.radiotap_len); TEST_ASSERT_FALSE(frame.has_rssi); }
static void test_radiotap_alignment_extension(void)
{
    unsigned i; le16(bytes+2,34); le32(bytes+4,UINT32_C(0x8008002f));
    for(i=0;i<8;++i) bytes[16+i]=(uint8_t)(i+1);
    bytes[24]=0; bytes[25]=108; le16(bytes+26,2437); le16(bytes+28,0x00a0); bytes[30]=0xd6;
    bytes[31]=7; bytes[32]=5; bytes[33]=15; mac(bytes+34,0x0040); ok_radio(58);
    TEST_ASSERT_TRUE(frame.has_tsft); TEST_ASSERT_EQUAL_HEX64(UINT64_C(0x0807060504030201),frame.tsft);
    TEST_ASSERT_TRUE(frame.has_rate); TEST_ASSERT_EQUAL_UINT8(108,frame.rate);
    TEST_ASSERT_TRUE(frame.has_channel); TEST_ASSERT_EQUAL_UINT16(2437,frame.freq);
    TEST_ASSERT_EQUAL_UINT16(6,frame.channel); TEST_ASSERT_EQUAL_UINT16(0x00a0,frame.channel_flags);
    TEST_ASSERT_TRUE(frame.has_rssi); TEST_ASSERT_EQUAL_INT16(-42,frame.rssi_dbm);
    TEST_ASSERT_TRUE(frame.has_mcs); TEST_ASSERT_EQUAL_UINT8(7,frame.mcs_known);
    TEST_ASSERT_EQUAL_UINT8(5,frame.mcs_flags); TEST_ASSERT_EQUAL_UINT8(15,frame.mcs_index);
}
static void test_radiotap_skip_standard_fields(void)
{
    le16(bytes+2,16); le32(bytes+4,UINT32_C(0x00080034));
    bytes[8]=12; bytes[10]=9; bytes[11]=8; bytes[12]=0xc4; bytes[13]=7; bytes[14]=1; bytes[15]=4;
    mac(bytes+16,0x0040); ok_radio(40); TEST_ASSERT_EQUAL_INT16(-60,frame.rssi_dbm); TEST_ASSERT_EQUAL_UINT8(4,frame.mcs_index);
}
static void test_radiotap_unaligned_input_pointer(void)
{
    uint8_t unaligned[80]={0}; le16(unaligned+3,24); le32(unaligned+5,9);
    unaligned[9]=0x78; le16(unaligned+17,5180); mac(unaligned+25,0x0040);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_parse_frame(unaligned+1,48,127,&frame));
    TEST_ASSERT_EQUAL_UINT16(5180,frame.freq); TEST_ASSERT_EQUAL_UINT16(36,frame.channel); TEST_ASSERT_EQUAL_HEX64(0x78,frame.tsft);
}
static void test_radiotap_invalid_lengths(void)
{
    size_t i; for(i=0;i<8;++i) TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,i,127,&frame));
    le16(bytes+2,7); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,32,127,&frame));
    le16(bytes+2,33); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,32,127,&frame));
}
static void test_radiotap_truncated_field(void)
{ le16(bytes+2,9); le32(bytes+4,1); mac(bytes+9,0x0040); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,33,127,&frame)); }
static void test_radiotap_truncated_extension(void)
{ le16(bytes+2,8); le32(bytes+4,UINT32_C(0x80000000)); mac(bytes+8,0x0040); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,32,127,&frame)); }
static void test_radiotap_unknown_extension_field(void)
{ le16(bytes+2,12); le32(bytes+4,UINT32_C(0x80000000)); le32(bytes+8,1); mac(bytes+12,0x0040); TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_UNSUPPORTED,airtrace_parse_frame(bytes,36,127,&frame)); }
static void test_radiotap_bad_version(void)
{ bytes[0]=1; le16(bytes+2,8); mac(bytes+8,0x0040); TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_UNSUPPORTED,airtrace_parse_frame(bytes,32,127,&frame)); }
static void test_radiotap_fcs_present(void)
{
    le16(bytes+2,9); le32(bytes+4,2); bytes[8]=0x10; mac(bytes+9,0x0040);
    bytes[33]=0xde; bytes[34]=0xad; bytes[35]=0xbe; bytes[36]=0xef; ok_radio(37);
    TEST_ASSERT_TRUE(frame.fcs_present); TEST_ASSERT_EQUAL_size_t(0,frame.ie_count);
}
static void test_radiotap_fcs_absent(void)
{ le16(bytes+2,9); le32(bytes+4,2); mac(bytes+9,0x0040); ok_radio(33); TEST_ASSERT_FALSE(frame.fcs_present); }
static void test_radiotap_fcs_truncated(void)
{ le16(bytes+2,9); le32(bytes+4,2); bytes[8]=0x10; mac(bytes+9,0x0040); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,33,127,&frame)); }
static void test_radiotap_vendor_namespace(void)
{
    le16(bytes+2,18); le32(bytes+4,UINT32_C(0x40000000));
    bytes[8]=0x00; bytes[9]=0x11; bytes[10]=0x22; bytes[11]=1; le16(bytes+12,4);
    mac(bytes+18,0x0040); ok_radio(42);
    le16(bytes+12,5); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,42,127,&frame));
}
static void test_radiotap_namespace_reset(void)
{
    le16(bytes+2,13); le32(bytes+4,UINT32_C(0xa0000000)); le32(bytes+8,2);
    bytes[12]=0; mac(bytes+13,0x0040); ok_radio(37); TEST_ASSERT_TRUE(frame.has_flags);
}
static void test_radiotap_many_empty_extensions(void)
{
    size_t i; le16(bytes+2,88);
    for(i=4;i<84;i+=4) le32(bytes+i,UINT32_C(0x80000000));
    mac(bytes+88,0x0040); ok_radio(112);
}
static void test_radiotap_datapad_qos(void)
{
    le16(bytes+2,9); le32(bytes+4,2); bytes[8]=0x20; mac(bytes+9,0x0188);
    eapol(bytes+37,0x008a); ok_radio(144); TEST_ASSERT_EQUAL_UINT8(1,frame.eapol_msg);
}
static size_t tlv(uint8_t *p, uint16_t type, uint16_t size, const uint8_t *value)
{
    size_t total=4u+size;
    le16(p,type); le16(p+2,size);
    if(size!=0) memcpy(p+4,value,size);
    return (total+3u)&~(size_t)3u;
}
static void test_radiotap_tlv_partial_and_unknown_fields(void)
{
    const uint8_t flags[]={0}, tsft[]={1,2,3}, channel[]={0x85,9,0xa0,0};
    const uint8_t rssi[]={0xd6}, mcs[]={7,3}, s1g[6]={0}, usig[12]={0};
    size_t n=8;
    le32(bytes+4,UINT32_C(0x10000000));
    n+=tlv(bytes+n,1,sizeof flags,flags); n+=tlv(bytes+n,0,sizeof tsft,tsft);
    n+=tlv(bytes+n,3,sizeof channel,channel); n+=tlv(bytes+n,5,sizeof rssi,rssi);
    n+=tlv(bytes+n,19,sizeof mcs,mcs); n+=tlv(bytes+n,32,sizeof s1g,s1g);
    n+=tlv(bytes+n,33,sizeof usig,usig); n+=tlv(bytes+n,500,sizeof tsft,tsft);
    le16(bytes+2,(uint16_t)n); mac(bytes+n,0x0040); ok_radio(n+24);
    TEST_ASSERT_TRUE(frame.has_flags); TEST_ASSERT_TRUE(frame.has_tsft);
    TEST_ASSERT_EQUAL_HEX64(0x030201,frame.tsft);
    TEST_ASSERT_EQUAL_UINT16(2437,frame.freq); TEST_ASSERT_EQUAL_UINT16(6,frame.channel);
    TEST_ASSERT_EQUAL_INT16(-42,frame.rssi_dbm); TEST_ASSERT_TRUE(frame.has_mcs);
    TEST_ASSERT_EQUAL_UINT8(7,frame.mcs_known); TEST_ASSERT_EQUAL_UINT8(3,frame.mcs_flags);
    TEST_ASSERT_EQUAL_UINT8(0,frame.mcs_index);
}
static void test_radiotap_tlv_length_and_padding_errors(void)
{
    le32(bytes+4,UINT32_C(0x10000000)); le16(bytes+2,16);
    le16(bytes+8,5); le16(bytes+10,5); mac(bytes+16,0x0040);
    TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,40,127,&frame));
    le16(bytes+10,1); le16(bytes+2,13); mac(bytes+13,0x0040);
    TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,37,127,&frame));
    le16(bytes+2,11); mac(bytes+11,0x0040);
    TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,35,127,&frame));
}
static void test_radiotap_tlv_reserved_types_and_higher_bits(void)
{
    le32(bytes+4,UINT32_C(0x10000000)); le16(bytes+2,12); le16(bytes+8,29);
    mac(bytes+12,0x0040);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_MALFORMED,airtrace_parse_frame(bytes,36,127,&frame));
    le16(bytes+8,31);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_MALFORMED,airtrace_parse_frame(bytes,36,127,&frame));
    le32(bytes+4,UINT32_C(0x30000000));
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_MALFORMED,airtrace_parse_frame(bytes,36,127,&frame));
}
static void test_radiotap_vendor_then_standard_namespace(void)
{
    le16(bytes+2,26); le32(bytes+4,UINT32_C(0xc0000000));
    le32(bytes+8,UINT32_C(0xa0000001)); le32(bytes+12,UINT32_C(0x20));
    bytes[16]=0x12; bytes[17]=0x34; bytes[18]=0x56; bytes[19]=1;
    le16(bytes+20,3); bytes[22]=0xaa; bytes[23]=0xbb; bytes[24]=0xcc; bytes[25]=0xce;
    mac(bytes+26,0x0040); ok_radio(50); TEST_ASSERT_EQUAL_INT16(-50,frame.rssi_dbm);
    le16(bytes+20,4);
    TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_parse_frame(bytes,50,127,&frame));
}
static void test_radiotap_conflicting_namespaces(void)
{
    le16(bytes+2,8); le32(bytes+4,UINT32_C(0x60000000)); mac(bytes+8,0x0040);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_MALFORMED,airtrace_parse_frame(bytes,32,127,&frame));
}

static void check_eapol(uint16_t info, uint8_t message)
{
    mac(bytes,0x0208); ok_raw(24+eapol(bytes+24,info));
    TEST_ASSERT_TRUE(frame.has_eapol); TEST_ASSERT_EQUAL_UINT8(message,frame.eapol_msg);
    TEST_ASSERT_EQUAL_HEX16(info,frame.eapol_key_info); TEST_ASSERT_EQUAL_HEX64(7,frame.eapol_replay_counter);
}
static void test_eapol_message_1(void) { check_eapol(0x008a,1); }
static void test_eapol_message_2(void) { check_eapol(0x010a,2); }
static void test_eapol_message_3(void) { check_eapol(0x03ca,3); }
static void test_eapol_message_4(void) { check_eapol(0x030a,4); }
static void test_eapol_wpa_message_4(void)
{ mac(bytes,0x0108); eapol(bytes+24,0x0109); bytes[36]=254; ok_raw(131); TEST_ASSERT_EQUAL_UINT8(4,frame.eapol_msg); }
static void test_eapol_group_key_unclassified(void) { check_eapol(0x0382,0); }
static void test_eapol_request_error_unclassified(void)
{ check_eapol(0x090a,0); check_eapol(0x050a,0); }
static void test_eapol_wrong_llc(void)
{ mac(bytes,0x0108); eapol(bytes+24,0x010a); bytes[25]=0xab; ok_raw(131); TEST_ASSERT_FALSE(frame.has_eapol); }
static void test_eapol_protected_not_decoded(void)
{ mac(bytes,0x4108); eapol(bytes+24,0x010a); ok_raw(131); TEST_ASSERT_FALSE(frame.has_eapol); }
static void test_eapol_fragment_not_decoded(void)
{ mac(bytes,0x0108); le16(bytes+22,1); eapol(bytes+24,0x010a); ok_raw(131); TEST_ASSERT_FALSE(frame.has_eapol); }
static void test_eapol_declared_length_truncated(void)
{ mac(bytes,0x0108); eapol(bytes+24,0x010a); fails_raw(130); be16(bytes+34,96); fails_raw(131); }
static void test_eapol_key_data_length_mismatch(void)
{ mac(bytes,0x0108); eapol(bytes+24,0x010a); be16(bytes+129,1); fails_raw(131); }
static void test_eapol_qos(void)
{ mac(bytes,0x0188); le16(bytes+24,3); eapol(bytes+26,0x010a); ok_raw(133); TEST_ASSERT_EQUAL_UINT8(2,frame.eapol_msg); }
static void test_eapol_qos_ht_control(void)
{
    size_t i; mac(bytes,0x8188); le16(bytes+24,3); bytes[26]=0x81;
    eapol(bytes+30,0x010a); ok_raw(137);
    TEST_ASSERT_EQUAL_UINT8(2,frame.eapol_msg); TEST_ASSERT_EQUAL_size_t(30,frame.header_len);
    for(i=24;i<30;++i) fails_raw(i);
}
static void test_eapol_amsdu_and_null_data_not_decoded(void)
{
    mac(bytes,0x0188); le16(bytes+24,0x0080); eapol(bytes+26,0x010a); ok_raw(133);
    TEST_ASSERT_FALSE(frame.has_eapol);
    mac(bytes,0x0148); eapol(bytes+24,0x010a); ok_raw(131); TEST_ASSERT_FALSE(frame.has_eapol);
}
static void test_eapol_first_fragment_not_decoded(void)
{ mac(bytes,0x0508); eapol(bytes+24,0x010a); ok_raw(131); TEST_ASSERT_TRUE(frame.more_fragments); TEST_ASSERT_FALSE(frame.has_eapol); }
static void test_eapol_non_key_packet(void)
{ mac(bytes,0x0108); eapol(bytes+24,0x010a); bytes[33]=0; ok_raw(131); TEST_ASSERT_FALSE(frame.has_eapol); }
static void test_eapol_short_and_unknown_descriptors(void)
{
    mac(bytes,0x0108); eapol(bytes+24,0x010a); be16(bytes+34,0); fails_raw(36);
    be16(bytes+34,94); fails_raw(130);
    be16(bytes+34,1); bytes[36]=1; ok_raw(37); TEST_ASSERT_FALSE(frame.has_eapol);
}
static void test_eapol_key_data_and_trailing_padding(void)
{
    mac(bytes,0x0108); eapol(bytes+24,0x010a); be16(bytes+34,97); be16(bytes+129,2);
    bytes[131]=0xde; bytes[132]=0xad; ok_raw(137);
    TEST_ASSERT_EQUAL_UINT8(2,frame.eapol_msg);
}
static void test_authentication_algorithm_specific_tail(void)
{
    mac(bytes,0x00b0); le16(bytes+24,3); le16(bytes+26,1); le16(bytes+28,0);
    bytes[30]=19; bytes[31]=0xff; bytes[32]=0x7f; ok_raw(33);
    TEST_ASSERT_TRUE(frame.has_auth); TEST_ASSERT_EQUAL_UINT16(3,frame.auth_algorithm);
    TEST_ASSERT_EQUAL_size_t(0,frame.ie_count);
}
static void test_management_protected_body_not_decoded(void)
{
    mac(bytes,0x40c0); bytes[24]=0xff; ok_raw(25);
    TEST_ASSERT_TRUE(frame.protected_frame); TEST_ASSERT_FALSE(frame.has_reason);
}

static void pcap_header(int big, int nano, uint32_t link)
{
    memset(bytes,0,sizeof bytes); order32(bytes,nano ? UINT32_C(0xa1b23c4d):UINT32_C(0xa1b2c3d4),big);
    order16(bytes+4,2,big); order16(bytes+6,4,big); order32(bytes+16,65535,big); order32(bytes+20,link,big);
}
static void pcap_record(int big, uint32_t frac, uint32_t caplen, uint32_t origlen)
{ order32(bytes+24,123,big); order32(bytes+28,frac,big); order32(bytes+32,caplen,big); order32(bytes+36,origlen,big); }
static void open_bytes(size_t n)
{
    capture=tmpfile(); TEST_ASSERT_NOT_NULL(capture);
    TEST_ASSERT_EQUAL_size_t(n,fwrite(bytes,1,n,capture)); rewind(capture);
}
static void check_pcap_variant(int big,int nano)
{
    airtrace_pcap reader; airtrace_pcap_record record; uint8_t payload[64];
    pcap_header(big,nano,105); pcap_record(big,nano ? 123456789:123456,24,24); mac(bytes+40,0x0040); open_bytes(64);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_pcap_open(&reader,capture));
    TEST_ASSERT_EQUAL_INT(big,reader.big_endian); TEST_ASSERT_EQUAL_INT(nano,reader.nanosecond);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_pcap_next(&reader,payload,sizeof payload,&record));
    TEST_ASSERT_EQUAL_UINT32(123,record.ts_sec); TEST_ASSERT_EQUAL_UINT32(nano ? 123456789:123456000,record.ts_nsec);
    TEST_ASSERT_EQUAL_UINT32(24,record.captured_len); TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes+40,payload,24);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_EOF,airtrace_pcap_next(&reader,payload,sizeof payload,&record));
}
static void test_pcap_le_microseconds(void) { check_pcap_variant(0,0); }
static void test_pcap_be_microseconds(void) { check_pcap_variant(1,0); }
static void test_pcap_le_nanoseconds(void) { check_pcap_variant(0,1); }
static void test_pcap_be_nanoseconds(void) { check_pcap_variant(1,1); }
static void test_pcap_header_truncation(void)
{
    airtrace_pcap reader; size_t i; pcap_header(0,0,105);
    for(i=0;i<24;++i) { open_bytes(i); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_pcap_open(&reader,capture)); tearDown(); }
}
static void test_pcap_bad_magic(void)
{ airtrace_pcap reader; pcap_header(0,0,105); bytes[0]=0; open_bytes(24); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_pcap_open(&reader,capture)); }
static void test_pcap_bad_version(void)
{ airtrace_pcap reader; pcap_header(0,0,105); bytes[4]=3; open_bytes(24); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_pcap_open(&reader,capture)); }
static void test_pcap_unsupported_linktype(void)
{ airtrace_pcap reader; pcap_header(0,0,1); open_bytes(24); TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_UNSUPPORTED,airtrace_pcap_open(&reader,capture)); }
static void test_pcap_radiotap_linktype(void)
{ airtrace_pcap reader; pcap_header(0,0,127); open_bytes(24); TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_pcap_open(&reader,capture)); TEST_ASSERT_EQUAL_INT(127,reader.linktype); }
static void test_pcap_record_header_truncation(void)
{
    airtrace_pcap reader; airtrace_pcap_record record; uint8_t payload[64]; size_t i;
    pcap_header(0,0,105); pcap_record(0,123,24,24);
    for(i=1;i<16;++i) { open_bytes(24+i); TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_pcap_open(&reader,capture)); TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_TRUNCATED,airtrace_pcap_next(&reader,payload,sizeof payload,&record)); tearDown(); }
}
static airtrace_err next_capture(size_t n, size_t capacity)
{
    airtrace_pcap reader; airtrace_pcap_record record; uint8_t payload[64]; open_bytes(n);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_pcap_open(&reader,capture));
    return airtrace_pcap_next(&reader,payload,capacity,&record);
}
static void test_pcap_record_payload_truncation(void)
{ pcap_header(0,0,105); pcap_record(0,123,24,24); TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_TRUNCATED,next_capture(63,64)); }
static void test_pcap_record_exceeds_capacity(void)
{ pcap_header(0,0,105); pcap_record(0,123,24,24); TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_CAPACITY,next_capture(64,23)); }
static void test_pcap_record_exceeds_original(void)
{ pcap_header(0,0,105); pcap_record(0,123,24,23); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,next_capture(64,64)); }
static void test_pcap_record_exceeds_snaplen(void)
{ pcap_header(0,0,105); le32(bytes+16,23); pcap_record(0,123,24,24); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,next_capture(64,64)); }
static void test_pcap_invalid_timestamp_fraction(void)
{ pcap_header(0,0,105); pcap_record(0,1000000,24,24); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,next_capture(64,64)); }
static void test_pcap_zero_snaplen(void)
{ airtrace_pcap reader; pcap_header(0,0,105); le32(bytes+16,0); open_bytes(24); TEST_ASSERT_NOT_EQUAL(AIRTRACE_OK,airtrace_pcap_open(&reader,capture)); }

static void test_pcap_high_linktype_metadata_rejected(void)
{
    airtrace_pcap reader; pcap_header(0,0,UINT32_C(0x24000069)); open_bytes(24);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_UNSUPPORTED,airtrace_pcap_open(&reader,capture));
}
static void test_pcap_nanosecond_fraction_out_of_range(void)
{
    pcap_header(1,1,105); pcap_record(1,UINT32_C(1000000000),24,24);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_MALFORMED,next_capture(64,64));
}
static void test_pcap_capacity_failure_is_terminal(void)
{
    airtrace_pcap reader; airtrace_pcap_record record; uint8_t payload[64];
    pcap_header(0,0,105); pcap_record(0,123,24,24); open_bytes(64);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_pcap_open(&reader,capture));
    memset(&record,0xff,sizeof record);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_CAPACITY,airtrace_pcap_next(&reader,payload,23,&record));
    TEST_ASSERT_NULL(reader.file); TEST_ASSERT_EQUAL_UINT32(0,record.captured_len);
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_INVALID,airtrace_pcap_next(&reader,payload,sizeof payload,&record));
}
static void test_pcap_null_arguments(void)
{
    airtrace_pcap reader={0}; airtrace_pcap_record record; uint8_t payload[1];
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_INVALID,airtrace_pcap_open(NULL,NULL));
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_INVALID,airtrace_pcap_open(&reader,NULL));
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_INVALID,airtrace_pcap_next(NULL,payload,sizeof payload,&record));
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_INVALID,airtrace_pcap_next(&reader,NULL,0,&record));
    TEST_ASSERT_EQUAL_INT(AIRTRACE_ERR_INVALID,airtrace_pcap_next(&reader,payload,sizeof payload,NULL));
}

int main(void)
{
    UNITY_BEGIN();
#define T(name) RUN_TEST(test_##name)
    T(null_input_output); T(unknown_linktype); T(mac_truncation_every_prefix); T(error_clears_output);
    T(mac_fields_and_flags); T(addr4_qos); T(addr4_truncated); T(qos_truncated); T(bssid_ds_mapping); T(control_ack); T(bad_protocol_version);
    T(assoc_request); T(assoc_response); T(reassoc_request); T(reassoc_response); T(probe_request); T(probe_response);
    T(beacon); T(disassociation); T(authentication); T(deauthentication); T(management_fixed_truncation);
    T(supported_ies); T(hidden_and_binary_ssids); T(maximum_ssid); T(truncated_ie_header); T(truncated_ie_payload);
    T(invalid_known_ie_lengths); T(unknown_ie_skipped); T(ie_table_capacity);
    T(radiotap_empty); T(radiotap_alignment_extension); T(radiotap_skip_standard_fields); T(radiotap_unaligned_input_pointer);
    T(radiotap_invalid_lengths); T(radiotap_truncated_field); T(radiotap_truncated_extension); T(radiotap_unknown_extension_field);
    T(radiotap_bad_version); T(radiotap_fcs_present); T(radiotap_fcs_absent); T(radiotap_fcs_truncated);
    T(radiotap_vendor_namespace); T(radiotap_namespace_reset); T(radiotap_many_empty_extensions); T(radiotap_datapad_qos);
    T(radiotap_tlv_partial_and_unknown_fields); T(radiotap_tlv_length_and_padding_errors);
    T(radiotap_tlv_reserved_types_and_higher_bits); T(radiotap_vendor_then_standard_namespace); T(radiotap_conflicting_namespaces);
    T(eapol_message_1); T(eapol_message_2); T(eapol_message_3); T(eapol_message_4); T(eapol_wpa_message_4);
    T(eapol_group_key_unclassified); T(eapol_request_error_unclassified); T(eapol_wrong_llc); T(eapol_protected_not_decoded);
    T(eapol_fragment_not_decoded); T(eapol_declared_length_truncated); T(eapol_key_data_length_mismatch); T(eapol_qos);
    T(eapol_qos_ht_control); T(eapol_amsdu_and_null_data_not_decoded); T(eapol_first_fragment_not_decoded);
    T(eapol_non_key_packet); T(eapol_short_and_unknown_descriptors); T(eapol_key_data_and_trailing_padding);
    T(authentication_algorithm_specific_tail); T(management_protected_body_not_decoded);
    T(pcap_le_microseconds); T(pcap_be_microseconds); T(pcap_le_nanoseconds); T(pcap_be_nanoseconds); T(pcap_header_truncation);
    T(pcap_bad_magic); T(pcap_bad_version); T(pcap_unsupported_linktype); T(pcap_radiotap_linktype); T(pcap_record_header_truncation);
    T(pcap_record_payload_truncation); T(pcap_record_exceeds_capacity); T(pcap_record_exceeds_original); T(pcap_record_exceeds_snaplen);
    T(pcap_invalid_timestamp_fraction); T(pcap_zero_snaplen);
    T(pcap_high_linktype_metadata_rejected); T(pcap_nanosecond_fraction_out_of_range);
    T(pcap_capacity_failure_is_terminal); T(pcap_null_arguments);
#undef T
    return UNITY_END();
}
