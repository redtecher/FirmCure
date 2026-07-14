/*
 * apmib 完整 stub — 覆盖 boa 从 libapmib.so 导入的所有符号
 * 不链接 libc，write/memset 从 boa 已加载的 libc.so.0 解析
 */
extern int write(int fd, const void *buf, unsigned int count);
extern void *memset(void *s, int c, unsigned int n);

static int slen(const char *s) { int n = 0; while (*s++) n++; return n; }
static void puts2(const char *s) { write(2, s, slen(s)); }

/* ============ apmib 接口 ============ */

int apmib_init(void) {
    puts2("[stub] apmib_init -> 1\n");
    return 1;
}

int apmib_reinit(void) { return 1; }

int apmib_get(int id, void *value) {
    memset(value, 0, 4);
    return 1;
}

int apmib_set(int id, void *value) { return 1; }
int apmib_getDef(int id, void *value) { memset(value, 0, 4); return 1; }
int apmib_setDef(int id, void *value) { return 1; }
int apmib_update(int t) { return 1; }
int apmib_updateFlash(int t) { return 1; }
int apmib_updateDef(void) { return 1; }
void apmib_sem_lock(void) {}
void apmib_sem_unlock(void) {}
int apmib_recov_wlanIdx(void) { return 1; }
int apmib_save_wlanIdx(void) { return 1; }
int apmib_init_HW(void) { return 1; }
int apmib_load_csconf(void) { return 1; }
int apmib_load_dsconf(void) { return 1; }
int apmib_load_hwconf(void) { return 1; }
void apmib_shm_free(void) {}

/* ============ boa 用到的其他 libapmib 导出函数 ============ */

int BrMode(void) { return 0; }
int DualWan(void) { return 0; }
int WdsMode(void) { return 0; }

int flash_read_raw_mib(void *buf, int offset, int len) {
    puts2("[stub] flash_read_raw_mib\n");
    return 0;
}

int flash_write_raw_mib(void *buf, int offset, int len) {
    return 0;
}

void getArpPara(void) {}

int getCPUFormFile(void *buf) {
    memset(buf, 0, 4);
    return 0;
}

int getDataFormFile(void *a, void *b) {
    return 0;
}

int mib_search_by_id(int id) {
    return 0;
}

int PppoeDhcpGet(void) { return 0; }

int rtl_name_to_mtdblock(const char *name) {
    return -1;
}

int save_cs_to_file(const char *path) {
    return 0;
}

int set_timeZone(void) { return 0; }

int swapWLANIdxForCwmp(int idx) { return 0; }

int update_tblentry(int id, void *val) { return 0; }
