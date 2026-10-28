/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Android libraries as Mach-O dylibs, made ahead of time (Husk 3.2: running Android code with no JIT).
 *
 * The loader runs a library from memory it copies the image into and rewrites (svc, x18, tpidr_el0, ctr_el0, adr/adrp to data), which
 * needs executable memory iOS only grants to a debugged process. A dylib is code iOS runs once it is signed, so the loader's own
 * mapping and rewriting (tl_ld_aot_build) run ahead of time and the result is written as one:
 *
 *   __TEXT  r-x   the Mach-O header with the manifest (__husk_manifest), padded to 16 KiB, then __husk_image: the image at its own
 *                 vaddr layout with every code rewrite applied, its stub pages and a thread-block page
 *   __DATA  rw-   __husk_data: the image as the file has it, the rest zero -- relocated at run time; the stubs' data slots and the
 *                 thread block, which the loader fills
 *   __LINKEDIT    empty fixups, export trie and symbol table (dyld wants them); a code signature is added by whoever signs it
 *
 * The distance from __husk_image to __husk_data is the image's size, the delta the rewrites were made for; dyld keeps segment
 * distances, so the patched code finds its data wherever the dylib is loaded. The loader imports such a dylib from the folder given
 * to tl_ld_set_aot_dir (see husk-tl-ld.h).
 */
#ifndef HUSK_TL_AOT_H
#define HUSK_TL_AOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "husk-tl-ld.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Make `out_path` from the arm64 library `file` (named `name`, as the loader will ask for it), for iOS or for macOS. The file is
 * written beside out_path and renamed into place, so a reader never sees half of one. Unsigned. `info` (optional) receives the
 * counts of what was rewritten; its text is no longer valid. Returns false with a reason in err.
 */
bool tl_aot_make_dylib(const char *name, const uint8_t *file, size_t flen, const char *out_path, bool ios, tl_ld_aot_image *info,
                       char *err, size_t errlen);

/*
 * Get an app ready to run with no JIT: every arm64 library in its APKs (the .so files under lib/arm64-v8a; the first APK that has a library wins,
 * as the loader's search does) as a dylib in cache_dir, aot-<hash>-<library>.dylib, signed with the developer certificate in p12
 * (husk-tl-codesign.h). A dylib already there is only signed again when cert_tag (any string naming the certificate) differs from
 * the one it was signed with, which is kept beside it in <dylib>.signer. progress (optional) is called before each library.
 * An entry of apks ending in .so is a library file itself (the Java runtime's own natives).
 * Returns how many libraries are ready, or -1 with a reason in err.
 */
typedef void (*tl_aot_progress_fn)(void *user, int index, int total, const char *library);
int husk_aot_prepare(const char *const *apks, int napks, const char *cache_dir, const uint8_t *p12, size_t p12_len,
                     const char *password, const char *cert_tag, tl_aot_progress_fn progress, void *user, char *err, size_t errlen);

#ifdef __cplusplus
}
#endif

#endif /* HUSK_TL_AOT_H */
