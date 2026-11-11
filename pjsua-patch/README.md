# The pjsua patch (`pjsua-patch/`)

`pjsua-btck.patch` modifies two files of the stock `pjsua` sample app from
[pjproject](https://github.com/pjsip/pjproject): `pjsua_app.c` and `pjsua_app_legacy.c`. The
client in [`../service/`](../service/) needs it for the photo, the answering machine and the live
view. Ring detection alone works with stock pjsua.

## What it changes

1. **One AVI per call.** Stock pjsua writes every call into one AVI file. The patched version
   rotates to a fresh, timestamped `<base>_<epoch>_<seq>.avi` each time the call that owns the
   recorder ends, and logs `BTCK-AVI-START <file>` and `BTCK-AVI-DONE <file>`. The service reads
   those two markers. Only one call at a time is connected to the recorder. If the recorder cannot
   be created, pjsua starts anyway, without video capture (in stock pjsua, that error is fatal).
2. **The live-view offer (§10).** On an **outgoing** offer only, when `BTCK_DEVADDR` is set in the
   environment, the patched pjsua adds an `a=DEVADDR:<uuid>` session attribute, which routes the
   call to the door station's camera. It also replaces the video direction with `sendrecv`. Incoming
   calls (rings) are marked when they arrive and are never touched. With `BTCK_DEVADDR` unset, this
   part does nothing.
3. **Bigger console buffers** (128 → 512 bytes) in the legacy console UI. A JSON-RPC open command
   (§8) or a long SIP URI typed on stdin no longer gets truncated.

The audio track in the AVI (`--rec-avi-audio`) is already in upstream pjproject. The patch does not
add it.

## Base revision

The patch applies to pjproject commit **`8c211fd0d054e5de6a882a544198886ba8bcb3c9`** (master,
2026-10-23, version 2.17.0). It does **not** apply to the `2.17` release tag, which is older.

```bash
git init pjproject && cd pjproject
git remote add origin https://github.com/pjsip/pjproject.git
git fetch --depth 1 origin 8c211fd0d054e5de6a882a544198886ba8bcb3c9
git checkout FETCH_HEAD
git apply --check /path/to/pjsua-btck.patch && git apply /path/to/pjsua-btck.patch
```

## Build

Same as [`scripts/00-setup-toolchain.sh`](../scripts/00-setup-toolchain.sh), with two differences:
the base revision above, and video turned on. Video needs the ffmpeg development packages
(`libavcodec-dev`, `libavformat-dev`, `libswscale-dev`), and this `pjlib/include/pj/config_site.h`:

```c
#define PJ_HAS_SSL_SOCK 1
#define PJMEDIA_HAS_SRTP 1
#define PJMEDIA_HAS_VIDEO 1
#define PJMEDIA_HAS_FFMPEG 1
#define PJMEDIA_HAS_FFMPEG_CODEC_H264 1
#define PJMEDIA_HAS_FFMPEG_VID_CODEC 1
```

```bash
./configure --with-mbedtls=<prefix> CFLAGS="-fPIC -I<prefix>/include" LDFLAGS="-L<prefix>/lib"
make dep && make -j"$(nproc)"
# binary: pjsip-apps/bin/pjsua-x86_64-pc-linux-gnu
```

`<prefix>` is where mbedTLS 3.6.x is installed (§4).

## Checksum

The author rebuilt this patch from scratch on the same configured tree that produced the
deployed binary, and got a byte-identical binary (sha256 starting `83a40e4fec813b4d`). That is the
value in `PJSUA_SHA16`. **You will not get that hash**: compiler, flags, library versions and paths
all change it. Hash your own build and put the result in `PJSUA_SHA16` (see
[`../service/README.md`](../service/README.md#2-pin-the-binary-checksum--required)).

## License

pjproject is distributed under the GNU GPL, version 2 or (at your option) any later version.
This patch is a derivative of pjproject's files and is released under the same terms
(GPL-2.0-or-later), **not** under the MIT license that covers the rest of this repository.
