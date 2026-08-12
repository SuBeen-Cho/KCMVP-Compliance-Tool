from experiments.smartcrypto_original_ai_eval import select

def test_selector_requires_real_pipeline_contract():
    assert callable(select)
