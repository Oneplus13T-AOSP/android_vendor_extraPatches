# Camera framework patch review (2026-11-09)

frameworks,av/0009 clears mOplusUserData in StagefrightRecorder::reset(), alongside
rotation and GPS parameters. The existing OplusUserData parameter handling stores
the payload in the recorder and forwards it to MPEG4Writer's moov/udta/oplu box.
Without clearing, resetting/reusing that recorder for another recording can emit
the previous recording's OPlus metadata (for example, after HDR -> SDR).

The follow-up patch was applied to an isolated copy of the current Android 17
StagefrightRecorder with patches 0002 and 0005, and checked for clean application
and whitespace. Full framework compilation and the HDR -> reset -> SDR recording
sequence remain untested. This is separate from the portrait EIS renderer error.

This repository remains at its relocated backup path. Do not run vendorsetup.sh
against the live source while it is being used to build another device. The
framework patch has deliberately not been applied to that active source tree.
Move the patch repository back to vendor/extraPatches for the pagani build workflow.
