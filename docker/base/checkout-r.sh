#!/bin/bash -eu
#
# Check out R trunk into $SRC/r-source, tolerating a flaky SVN server.
#
# A full checkout streams several hundred megabytes over a single HTTP
# connection, and svn.r-project.org occasionally cuts it off partway
# ("ra_serf: The server sent a truncated HTTP response body", 2026-09-26),
# which used to fail the whole image build.  An interrupted checkout leaves
# a working copy that `svn cleanup` unlocks and a repeated `svn checkout`
# resumes, so each attempt after the first only fetches what is missing.
#
# The revision is resolved once up front and every attempt pins to it, so
# a commit landing on trunk between attempts cannot leave the working copy
# at mixed revisions (and /opt/r-svn-revision is a single clean number).

URL=https://svn.r-project.org/R/trunk
DEST="$SRC/r-source"
ATTEMPTS=5
DELAY=30

attempt() {
    local n
    for n in $(seq 1 "$ATTEMPTS"); do
        if "$@"; then
            return 0
        fi
        echo "checkout-r.sh: '$*' failed (attempt $n of $ATTEMPTS)" >&2
        if [ "$n" -lt "$ATTEMPTS" ]; then
            sleep "$DELAY"
        fi
    done
    return 1
}

resume_checkout() {
    if [ -d "$DEST/.svn" ]; then
        svn cleanup "$DEST"
    fi
    svn checkout --depth=infinity -r "$REV" "$URL" "$DEST"
}

REV=$(attempt svn info --show-item revision "$URL") || exit 1
echo "checkout-r.sh: checking out $URL at r$REV"

attempt resume_checkout || exit 1

svnversion "$DEST" > /opt/r-svn-revision
