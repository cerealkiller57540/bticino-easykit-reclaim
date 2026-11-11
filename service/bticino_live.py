"""
bticino_live.py - streams the video of a door station call live to go2rtc.

pjsua (bticino-doorbell service) writes one raw AVI per call into RUN_DIR,
named rx_<epoch>_<seq>.avi, created at 0 bytes then filled during the call.
We follow the growing file and feed it to ffmpeg through a pipe: read
directly (-follow), the AVI demuxer freezes the end of the data at the size
seen when it opened the file and stops after 2 frames.

Stops when: the file is deleted or moved (st_nlink == 0), it stops growing
for IDLE_S, or MAX_S is reached. Read-only on RUN_DIR.
Publishes to 127.0.0.1: go2rtc requires no password locally,
so there is no secret on the command line.
"""
import os
import re
import subprocess
import sys
import threading
import time

RUN_DIR = os.environ.get("BTCK_LIVE_DIR", "/run/bticino")
RTSP_URL = os.environ.get("BTCK_LIVE_URL", "rtsp://127.0.0.1:8554/portier")
IDLE_S = 3.0
MAX_S = 180.0
POLL_S = 0.2
CHUNK = 262144
NAME_RE = re.compile(r"^rx_\d+_\d+\.avi$")

FFMPEG = [
    "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
    "-f", "avi", "-probesize", "200000", "-analyzeduration", "0",
    "-use_wallclock_as_timestamps", "1", "-i", "pipe:0",
    # Audio on the video's wall-clock time base (first_pts=0 shifted it by several hours:
    # HA's stream worker then dropped the video when remuxing to mp4). min_hard_comp=0.5 absorbs
    # the pipe's 50 ms bursts without gaps. "?" = no failure if the AVI has no audio.
    "-map", "0:v:0", "-map", "0:a:0?",
    "-af", "aresample=async=1:min_hard_comp=0.5", "-c:a", "aac", "-b:a", "32k", "-ar", "16000", "-ac", "1",
    "-fps_mode", "passthrough", "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
    "-g", "18", "-pix_fmt", "yuv420p",
    "-rtsp_transport", "tcp", "-f", "rtsp", RTSP_URL,
]


def log(msg):
    print("[bticino-live] " + msg, flush=True)


def candidates():
    try:
        names = os.listdir(RUN_DIR)
    except OSError:
        return []
    return [n for n in names if NAME_RE.match(n)]


def pump(f, proc, t0):
    """Copies the file to ffmpeg's stdin while it is alive. Returns the reason it stopped."""
    last = time.monotonic()
    while True:
        if time.monotonic() - t0 > MAX_S:
            return "duree max"
        if proc.poll() is not None:
            return "ffmpeg sorti rc=%s" % proc.returncode
        b = f.read(CHUNK)
        if b:
            try:
                proc.stdin.write(b)
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                return "tube ferme"
            last = time.monotonic()
            continue
        if os.fstat(f.fileno()).st_nlink == 0:
            return "fichier retire"
        if time.monotonic() - last > IDLE_S:
            return "plus de donnees"
        time.sleep(0.05)


def stream(path):
    t0 = time.monotonic()
    try:
        f = open(path, "rb", buffering=0)
    except OSError as e:
        log("cannot open: %s" % e)
        return
    try:
        proc = subprocess.Popen(FFMPEG, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE)
    except OSError as e:
        log("ffmpeg not found/unreachable: %s" % e)
        return
    err = []
    t = threading.Thread(target=lambda: err.extend(proc.stderr.read().decode(errors="replace").splitlines()[-3:]),
                         daemon=True)
    t.start()
    log("live started: " + os.path.basename(path))
    try:
        reason = pump(f, proc, t0)
    finally:
        f.close()
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    t.join(timeout=1)
    log("live stopped (%s) after %.1f s" % (reason, time.monotonic() - t0))
    for line in err:
        if "Invalid buffer size" not in line and "Error submitting packet" not in line:
            log("ffmpeg: " + line[:200])


def main():
    # Files already present at startup belong to a current or past call:
    # they are not streamed, unless still empty (recorder armed for the next call).
    done = set(n for n in candidates()
               if os.path.getsize(os.path.join(RUN_DIR, n)) > 0)
    log("watching %s (%d skipped)" % (RUN_DIR, len(done)))
    while True:
        for n in sorted(candidates()):
            if n in done:
                continue
            p = os.path.join(RUN_DIR, n)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if size > 0:
                done.add(n)
                stream(p)
        present = set(candidates())
        done &= present
        time.sleep(POLL_S)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
