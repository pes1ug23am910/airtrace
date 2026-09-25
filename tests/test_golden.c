#include "airtrace.h"
#include "airtrace_pcap.h"
#include "unity.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COLUMN_COUNT 22u
static const char *fixture_root;
static FILE *pcap_file, *oracle_file;
static uint8_t packet[65536];
static char context[256];

void setUp(void) { }
void tearDown(void)
{
    if (pcap_file != NULL) { (void)fclose(pcap_file); pcap_file=NULL; }
    if (oracle_file != NULL) { (void)fclose(oracle_file); oracle_file=NULL; }
}

static size_t split(char *line, char **fields)
{
    size_t count=1; char *p; fields[0]=line;
    for(p=line;*p!='\0';++p) {
        if(*p=='\n'||*p=='\r') { *p='\0'; break; }
        if(*p=='\t') { *p='\0'; if(count<COLUMN_COUNT) fields[count]=p+1; ++count; }
    }
    return count;
}
static unsigned long number(const char *s) { return strtoul(s,NULL,0); }
static int truth(const char *s) { return strcmp(s,"True")==0 || strcmp(s,"1")==0; }
static void compare_mac(const char *expected, const uint8_t *actual)
{
    char rendered[18];
    if(*expected=='\0') return;
    (void)snprintf(rendered,sizeof rendered,"%02x:%02x:%02x:%02x:%02x:%02x",
                   actual[0],actual[1],actual[2],actual[3],actual[4],actual[5]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected,rendered,context);
}
static void compare_ssid(const char *expected, const airtrace_frame *frame)
{
    static const char hex[]="0123456789abcdef"; char rendered[65]; size_t i;
    if(*expected=='\0') return;
    TEST_ASSERT_TRUE_MESSAGE(frame->has_ssid,context);
    if(strcmp(expected,"<MISSING>")==0) { TEST_ASSERT_EQUAL_UINT8_MESSAGE(0,frame->ssid_len,context); return; }
    for(i=0;i<frame->ssid_len;++i) { rendered[2*i]=hex[frame->ssid[i]>>4]; rendered[2*i+1]=hex[frame->ssid[i]&15]; }
    rendered[2*i]='\0'; TEST_ASSERT_EQUAL_STRING_MESSAGE(expected,rendered,context);
}
static void compare_frame(char **fields, const airtrace_frame *frame)
{
    const uint8_t *da=frame->addrs[0], *sa=frame->addrs[1];
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(number(fields[2]),frame->type,context);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(number(fields[3]),frame->subtype,context);
    TEST_ASSERT_EQUAL_INT_MESSAGE(*fields[4]!='\0',frame->has_rssi,context);
    if(*fields[4]!='\0') TEST_ASSERT_EQUAL_INT16_MESSAGE(strtol(fields[4],NULL,10),frame->rssi_dbm,context);
    TEST_ASSERT_EQUAL_INT_MESSAGE(*fields[5]!='\0',frame->has_channel,context);
    if(*fields[5]!='\0') TEST_ASSERT_EQUAL_UINT16_MESSAGE(number(fields[5]),frame->freq,context);
    if(*fields[6]!='\0') { TEST_ASSERT_TRUE_MESSAGE(frame->has_ds_channel,context); TEST_ASSERT_EQUAL_UINT16_MESSAGE(number(fields[6]),frame->channel,context); }
    compare_mac(fields[7],frame->addrs[0]); compare_mac(fields[8],frame->addrs[1]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(*fields[9]!='\0',frame->has_bssid,context);
    compare_mac(fields[9],frame->bssid); compare_ssid(fields[10],frame);
    TEST_ASSERT_EQUAL_INT_MESSAGE(*fields[11]!='\0',frame->has_seq,context);
    if(*fields[11]!='\0') TEST_ASSERT_EQUAL_UINT16_MESSAGE(number(fields[11]),frame->seq,context);
    TEST_ASSERT_EQUAL_INT_MESSAGE(truth(fields[12]),frame->retry,context);
    TEST_ASSERT_EQUAL_INT_MESSAGE(truth(fields[13]),frame->protected_frame,context);
    TEST_ASSERT_EQUAL_INT_MESSAGE(*fields[14]!='\0',frame->has_status,context);
    if(*fields[14]!='\0') TEST_ASSERT_EQUAL_UINT16_MESSAGE(number(fields[14]),frame->status_code,context);
    TEST_ASSERT_EQUAL_INT_MESSAGE(*fields[15]!='\0',frame->has_reason,context);
    if(*fields[15]!='\0') TEST_ASSERT_EQUAL_UINT16_MESSAGE(number(fields[15]),frame->reason_code,context);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(number(fields[16]),frame->eapol_msg,context);
    TEST_ASSERT_EQUAL_INT_MESSAGE(truth(fields[17]),frame->to_ds,context);
    TEST_ASSERT_EQUAL_INT_MESSAGE(truth(fields[18]),frame->from_ds,context);
    if(frame->type==2) {
        if(frame->to_ds) da=frame->addrs[2];
        if(frame->from_ds) sa=frame->to_ds ? frame->addrs[3] : frame->addrs[2];
    }
    compare_mac(fields[19],da); compare_mac(fields[20],sa);
}
static void compare_capture(const char *name, size_t expected_count, size_t expected_unsupported)
{
    char path[1024], line[4096], timestamp[64]; char *fields[COLUMN_COUNT];
    airtrace_pcap reader; airtrace_pcap_record record; airtrace_frame frame;
    size_t count=0, unsupported=0; airtrace_err result;
    (void)snprintf(path,sizeof path,"%s/%s.pcap",fixture_root,name);
    pcap_file=fopen(path,"rb"); TEST_ASSERT_NOT_NULL_MESSAGE(pcap_file,path);
    (void)snprintf(path,sizeof path,"%s/%s.tsv",fixture_root,name);
    oracle_file=fopen(path,"r"); TEST_ASSERT_NOT_NULL_MESSAGE(oracle_file,path);
    TEST_ASSERT_NOT_NULL(fgets(line,sizeof line,oracle_file));
    TEST_ASSERT_EQUAL_INT(AIRTRACE_OK,airtrace_pcap_open(&reader,pcap_file));
    while((result=airtrace_pcap_next(&reader,packet,sizeof packet,&record))==AIRTRACE_OK) {
        ++count; (void)snprintf(context,sizeof context,"%s frame %zu",name,count);
        TEST_ASSERT_NOT_NULL_MESSAGE(fgets(line,sizeof line,oracle_file),context);
        TEST_ASSERT_EQUAL_size_t_MESSAGE(COLUMN_COUNT,split(line,fields),context);
        TEST_ASSERT_EQUAL_size_t_MESSAGE(count,number(fields[0]),context);
        (void)snprintf(timestamp,sizeof timestamp,"%" PRIu32 ".%09" PRIu32,record.ts_sec,record.ts_nsec);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(fields[1],timestamp,context);
        result=airtrace_parse_frame(packet,record.captured_len,reader.linktype,&frame);
        if(number(fields[21])!=0) {
            TEST_ASSERT_EQUAL_INT_MESSAGE(AIRTRACE_ERR_UNSUPPORTED,result,context); ++unsupported;
        } else {
            TEST_ASSERT_EQUAL_INT_MESSAGE(AIRTRACE_OK,result,context); compare_frame(fields,&frame);
        }
    }
    TEST_ASSERT_EQUAL_INT(AIRTRACE_EOF,result);
    TEST_ASSERT_NULL_MESSAGE(fgets(line,sizeof line,oracle_file),"Oracle contains extra rows");
    TEST_ASSERT_EQUAL_size_t(expected_count,count); TEST_ASSERT_EQUAL_size_t(expected_unsupported,unsupported);
    (void)printf("Compared %zu frames (%zu rejected protocol versions) against tshark: %s\n",count,unsupported,name);
}
static void test_wpa_induction_against_tshark(void) { compare_capture("wpa-Induction",1093,10); }
static void test_nokia_join_against_tshark(void) { compare_capture("Network_Join_Nokia_Mobile",1180,0); }

int main(int argc, char **argv)
{
    if(argc!=2) { (void)fprintf(stderr,"usage: %s FIXTURE_DIRECTORY\n",argv[0]); return 2; }
    fixture_root=argv[1]; UNITY_BEGIN();
    RUN_TEST(test_wpa_induction_against_tshark);
    RUN_TEST(test_nokia_join_against_tshark);
    return UNITY_END();
}
