/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The guest dynamic linker.
 *
 * Takes an Android app's arm64 shared objects out of its APK and makes them run
 * inside this process: it maps them into the executable region (husk-tl-xmem),
 * relocates them, binds their imports to the bionic shims (husk-tl-bionic) or to
 * each other, and runs their constructors.
 *
 * It follows Android's linker where that decides whether a library works:
 *
 *   - an import is looked up first in the importing library's own scope -- itself,
 *     then its DT_NEEDED closure in breadth-first order -- and only then in the
 *     system. Unity's libraries each carry a private C++ runtime, and binding one
 *     library's exceptions to another's would corrupt both;
 *   - a library's dependencies are mapped, relocated and initialised before it;
 *   - initialisers receive (argc, argv, envp), as bionic passes them.
 *
 * It differs where the platform forces it. Code and data are two views of the same
 * pages (see husk-tl-xmem.h), so an address handed out for a data object is its
 * writable view and one for code is its executable view; the loader rewrites
 * code that would otherwise reach data through the wrong one.
 */
#ifndef HUSK_TL_LD_H
#define HUSK_TL_LD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tl_lib tl_lib;

/* Where libraries come from: the APKs' lib/arm64-v8a/ directories. */
#define TL_LD_MAX_APKS 48   /* a big game ships a dozen asset-pack splits besides its config ones (Disney Speedstorm: 16) */
bool tl_ld_add_apk(const char *path);
/* A split APK of the app about to start; added right after its base APK, whichever engine adds that. */
void tl_ld_queue_split(const char *path);
const char *tl_ld_queued_split(int index);              /* NULL past the last */

/* The APKs added, in order, for asset access; NULL past the last. */
struct tl_zip;
const struct tl_zip *tl_ld_apk_at(int index);

/* Bind every later import of `name` to `fn` instead of the library that defines it (the original is still reachable with tl_ld_sym). Call before the libraries load. */
void tl_ld_interpose(const char *name, void *fn);

/* Whether one of the APKs carries this arm64 library (an engine is told by the libraries it ships). */
bool tl_ld_has_lib(const char *name);
int tl_ld_apk_libs(void (*cb)(const char *name, uint64_t size, void *user), void *user);

/*
 * Load a library by file name or soname (already-loaded ones are returned as
 * they are), with everything it needs. Returns NULL and logs why on failure.
 * `name` may also be a system library ("libc.so"): that returns NULL without
 * logging an error, because the system is not a library this linker owns.
 */
tl_lib *tl_ld_load(const char *name);
/* Another folder to look for libraries in, by file name, after the APKs. */
void tl_ld_add_search_dir(const char *dir);

/* Run constructors for a library and anything it needs that has not run. */
bool tl_ld_init(tl_lib *lib);

/* A library already loaded, by file name or soname. */
tl_lib *tl_ld_find_lib(const char *name);

/* A symbol exported by `lib`, or (lib == NULL) by any loaded library, in load order. */
void *tl_ld_sym(tl_lib *lib, const char *name);
void *tl_ld_sym_deep(tl_lib *lib, const char *name, tl_lib **found_in);   /* the library, then its dependencies, as bionic's dlsym(handle) */

/* The library an address belongs to (either view), and the nearest exported symbol. */
tl_lib *tl_ld_lib_of(const void *addr);
void *tl_ld_lib_base(const tl_lib *lib);
const char *tl_ld_lib_name(const tl_lib *lib);
const char *tl_ld_symbol_at(const void *addr, const char **lib_name, const void **sym_addr);

/*
 * Walk loaded libraries the way dl_iterate_phdr does. The callback gets the load
 * bias (the executable view's address of vaddr 0), the library's name, its program
 * headers and their count; a non-zero return stops the walk.
 */
typedef int (*tl_ld_phdr_cb)(uintptr_t bias, const char *name, const void *phdr,
                             unsigned phnum, void *user);
int tl_ld_iterate(tl_ld_phdr_cb cb, void *user);

/*
 * Diagnostic probe: before the instruction at `vaddr` runs, call cb(regs) with the integer registers
 * x0..x28 as they stand (regs[i] is xi); then the instruction runs as usual. The instruction must not be
 * pc-relative. For finding out what guest code is doing when no debugger can follow it.
 */
bool tl_ld_probe(tl_lib *lib, uint64_t vaddr, void (*cb)(uint64_t *regs));

/*
 * The calling thread's virtual x18. Guest code never holds a live value in the real
 * register (the kernel zeroes it); its x18 lives in a TSD slot instead, and anything
 * that runs guest code on a signal frame saves it before and restores it after.
 */
uint64_t tl_vx18_get(void);
void tl_vx18_set(uint64_t v);

/* Imports that nothing provided, bound to a stub that logs on call. */
size_t tl_ld_unresolved_count(void);

/* How loud loading is: 0 quiet, 1 per-library summary, 2 every unresolved import. */
void tl_ld_set_verbosity(int v);

/* The program's own argv/envp for initialisers. Optional. */
void tl_ld_set_environment(char **argv, char **envp);

/*
 * Ahead of time (Husk 3.2): an arm64 library mapped and patched the way the loader does it, for a Mach-O dylib that runs with no
 * executable memory made at run time. `text` is the image with every code rewrite applied, then its stub pages and its thread-block
 * page: `size` bytes, which is also the distance the dylib must keep from `text` to its data copy. The data copy is the image as the
 * file lays it out (PT_LOAD contents at their vaddrs from base_vaddr, the rest zero), relocated at run time. `text` points into a
 * scratch region that tl_ld_aot_free releases. husk-tl-aot.h writes the dylib.
 */
typedef struct tl_ld_aot_image {
    const uint8_t *text;
    size_t size;
    uint64_t base_vaddr;               /* the vaddr at the start of the image */
    size_t npages, nstub;              /* 16 KiB pages of image and of stubs (one thread-block page follows the stubs) */
    size_t n_mixed;                    /* pages holding code and writable data (4 KiB-aligned libraries): data read at code addresses there is not relocated */
    size_t n_x18, n_x18_failed, n_svc, n_svc_far, n_adrp, n_adr, n_adr_failed, n_tpidr;
    void *region; size_t region_size;
    char err[160];
} tl_ld_aot_image;
bool tl_ld_aot_build(const char *name, const uint8_t *file, size_t flen, tl_ld_aot_image *out);

/* What a dylib made from a library records about it (section __TEXT,__husk_manifest), so the loader only imports a dylib that was
 * made from this exact file by a compatible loader. */
#define TL_AOT_MAGIC   "HUSKAOT1"
#define TL_AOT_VERSION 2u          /* bump whenever the rewrites change: an old dylib must not be imported */
typedef struct tl_aot_manifest {
    char magic[8];
    uint32_t version, page;            /* TL_AOT_VERSION; 16384 */
    uint64_t so_hash, so_size;         /* tl_aot_hash of the .so, and its size */
    uint64_t base_vaddr, npages, nstub, size;   /* as tl_ld_aot_image */
} tl_aot_manifest;
uint64_t tl_aot_hash(const uint8_t *p, size_t n);

/* Where the loader looks for <library>.dylib made ahead of time (NULL: nowhere; several folders separated by ':', searched in
 * order). A matching one is used instead of mapping the library into executable memory. */
void tl_ld_set_aot_dir(const char *dir);
void tl_ld_aot_free(tl_ld_aot_image *img);

#ifdef __cplusplus
}
#endif

#endif /* HUSK_TL_LD_H */
