#!/usr/bin/env python3
import sys, os, shutil, zipfile
sys.path.insert(0, os.path.dirname(__file__))
import rb_lib, rb_front, rb_p1a, rb_p1b, rb_p2a, rb_p2b, rb_end
rb_front.build(); rb_p1a.build(); rb_p1b.build(); rb_p2a.build(); rb_p2b.build(); rb_end.build()
miss = rb_lib.resolve(); print("unresolved refs:", miss)
out = "/mnt/user-data/outputs/CSA5103_CO4_Assignment4_Report.docx"; os.makedirs("/mnt/user-data/outputs", exist_ok=True); rb_lib.doc.save(out); print("saved", out, os.path.getsize(out))
