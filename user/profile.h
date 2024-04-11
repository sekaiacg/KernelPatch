#ifndef _KPU_PKG_CONFIG_H
#define _KPU_PKG_CONFIG_H

#include <string.h>

enum PKG_CONFIG_TYPE {
	PKG_NONE = 0,
	PKG_UID_UPDATE,
	PKG_REMOVE
};

typedef struct {
	char *pkgName;
	uint32_t exclude;
	uint32_t allow;
	uint32_t uid;
	uint32_t remove_uid;
	uint32_t to_uid;
	char *sctx;
	int type;
} Pkg_Config;

static inline void to_pkg_config(const char *pkgConfigStr, Pkg_Config *config) {
	char name[64];
	char ctx[64];
	sscanf(pkgConfigStr, "%[^,],%u,%u,%u,%u,%s",
	       name, &config->exclude, &config->allow, &config->uid, &config->to_uid,
	       ctx
	);
	config->pkgName = strdup(name);
	config->sctx = strdup(ctx);
}

static inline void release_pkg_config(Pkg_Config *config) {
	free(config->pkgName);
	free(config->sctx);
}

//
// static inline void pkg_config_to_buf(Pkg_Config *config, char *buf) {
// 	sprintf(buf, "%s,%d,%d,%u,%u,%s", config->pkgName,
// 	        config->exclude, config->allow, config->uid,
// 	        config->to_uid, config->sctx
// 	);
// }
//
typedef struct {
	char **data;
	int size;
	int capacity;
} StringArray;

static inline StringArray *initStringArray() {
	StringArray *arr = (StringArray *) malloc(sizeof(StringArray));
	arr->size = 0;
	arr->capacity = 10;
	arr->data = (char **) malloc(sizeof(char *) * arr->capacity);
	return arr;
}

static inline void addStringToArray(StringArray *arr, char *str) {
	if (arr->size >= arr->capacity) {
		arr->capacity *= 2;
		arr->data = (char **) realloc(arr->data, sizeof(char *) * arr->capacity);
	}
	arr->data[arr->size] = strdup(str);
	arr->size++;
}

static inline void freeStringArray(StringArray *arr) {
	for (int i = 0; i < arr->size; i++) {
		free(arr->data[i]);
	}
	free(arr->data);
	free(arr);
}

typedef struct {
	Pkg_Config **pkg_configs;
	int size;
	int capacity;
} PkgConfigArray;

static inline PkgConfigArray *initPkgConfigArray() {
	PkgConfigArray *arr = (PkgConfigArray *) malloc(sizeof(PkgConfigArray));
	arr->size = 0;
	arr->capacity = 10;
	arr->pkg_configs = (Pkg_Config **) malloc(sizeof(Pkg_Config) * arr->capacity);
	return arr;
}

static inline void addPkgConfigToArray(PkgConfigArray *arr, Pkg_Config *pkg_config) {
	if (arr->size >= arr->capacity) {
		arr->capacity *= 2;
		arr->pkg_configs = (Pkg_Config **) realloc(arr->pkg_configs, sizeof(Pkg_Config) * arr->capacity);
	}
	arr->pkg_configs[arr->size] = (Pkg_Config *) calloc(sizeof(Pkg_Config), 1);
	Pkg_Config *config = arr->pkg_configs[arr->size];
	if (config) {
		// char buf[128];
		// sscanf(str, "%s %u", &buf, &config->uid);
		// config->pkgName = strdup(buf);
		config->pkgName = pkg_config->pkgName;
		config->exclude = pkg_config->exclude;
		config->allow = pkg_config->allow;
		config->uid = pkg_config->uid;
		config->remove_uid = pkg_config->remove_uid;
		config->to_uid = pkg_config->to_uid;
		config->sctx = pkg_config->sctx;
		config->type = pkg_config->type;

		// char name[64];
		// char ctx[64];
		// sscanf(str, "%[^,],%d,%d,%u,%u,%s",
		//        &name, &config->exclude, &config->allow, &config->uid, &config->to_uid,
		//        &ctx
		// );
		// config->pkgName = strdup(name);
		// config->sctx = strdup(ctx);
	}
	arr->size++;
}

static inline void freePkgConfigArray(PkgConfigArray *arr) {
	for (int i = 0; i < arr->size; i++) {
		free(arr->pkg_configs[i]->pkgName);
		free(arr->pkg_configs[i]->sctx);
		free(arr->pkg_configs[i]);
	}
	free(arr->pkg_configs);
	free(arr);
}

#endif //_KPU_PKG_CONFIG_H
