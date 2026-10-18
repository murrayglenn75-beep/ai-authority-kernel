import hashlib
import unittest
from engineering.skill_admission import inspect_skill, approval_fingerprint
BODY=b"sample skill"
def record():
    return {"name":"debugging","source":"https://github.com/example/repo","revision":"a"*40,"sha256":hashlib.sha256(BODY).hexdigest(),"permissions":["read_workspace"],"approval_id":"ok"}
def approved(r): return {"ok": approval_fingerprint(r)}
class SkillAdmissionTests(unittest.TestCase):
    def test_approved(self): self.assertEqual(inspect_skill(record(),BODY,approved(record())),[])
    def test_default_denied(self): self.assertTrue(inspect_skill(record(),BODY))
    def test_mutated(self): self.assertTrue(inspect_skill(record(),b"tampered",approved(record())))
    def test_branch_not_pin(self):
        r=record();r["revision"]="main";self.assertTrue(inspect_skill(r,BODY,approved(record())))
    def test_unapproved_permissions(self):
        r=record();r["permissions"]=["all"];self.assertTrue(inspect_skill(r,BODY,{"ok"}))
    def test_approval_cannot_transfer_to_another_source(self):
        r=record(); r["source"]="https://github.com/other/repo"
        self.assertTrue(inspect_skill(r,BODY,approved(record())))
    def test_approval_cannot_expand_permissions(self):
        r=record(); r["permissions"]=["read_workspace","network"]
        self.assertTrue(inspect_skill(r,BODY,approved(record())))
    def test_invalid_payload(self): self.assertTrue(inspect_skill([],BODY))
    def test_unhashable_permission(self):
        r=record();r["permissions"]=[{}];self.assertTrue(inspect_skill(r,BODY,{"ok"}))
if __name__=="__main__": unittest.main()
