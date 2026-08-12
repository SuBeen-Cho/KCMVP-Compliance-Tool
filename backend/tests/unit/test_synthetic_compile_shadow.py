import zipfile

import pytest

from experiments.synthetic_compile_shadow import evaluate


def _archives(tmp_path, body="int example(void){return 0;}\n"):
    paths=[]
    for number in range(7):
        path=tmp_path/f"set-{number}.zip"
        with zipfile.ZipFile(path,"w") as archive:archive.writestr("src/example.c",body)
        paths.append(path)
    return paths


def test_synthetic_profile_is_never_authenticated_or_authorized(tmp_path):
    result=evaluate(_archives(tmp_path))
    assert result["aggregate"]["syntax_pass"]==7
    assert result["authenticated_compile_context_coverage"]==0
    assert result["semantic_authorization"]==0
    assert result["api_calls"]==0


def test_compile_failure_is_counted_not_promoted(tmp_path):
    result=evaluate(_archives(tmp_path,"this is not C\n"))
    assert result["aggregate"]["syntax_fail"]==7
    assert result["aggregate"]["pass_rate"]==0


def test_traversal_archive_is_rejected(tmp_path):
    paths=_archives(tmp_path)
    with zipfile.ZipFile(paths[0],"a") as archive:archive.writestr("../escape.c","int x;\n")
    with pytest.raises(ValueError,match="unsafe_archive_member"):evaluate(paths)
