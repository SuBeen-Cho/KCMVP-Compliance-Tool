from experiments.final_proxy_performance_summary import build


def test_current_and_historical_cohorts_stay_separate():
    sources=[{"source_id":f"set-{i}/x.c","lines":10} for i in range(1,8)]
    candidates=[{"payload":{"source_id":f"set-{(i%7)+1}/x.c"}} for i in range(265)]
    router={"stage_distribution":{"deterministic":{"count":30},"ai_ready":{"count":45},"hold":{"count":190}}}
    selective={"population":{"total":265},"routing_all":{},"routing_binary_eligible":{},"hold_analysis":{}}
    calibration={"calibration":{"heldout_metrics":{"n":2,"precision":1,"recall":1,"f1":1,"tp":1,"fp":0,"fn":0,"tn":1},"heldout_group_bootstrap_95_ci":{"f1":[1,1]}},"paired_binary":{"paired_n":2,"mcnemar_discordance_counts":{"left_only_correct":0,"right_only_correct":0},"mcnemar_exact_two_sided_p":1}}
    grounded={"population":{"exact_ai_ready":2},"conditions":{"grounded":{"verifier_pass_count":1,"verified_final_labels":{"abstain":1}}},"execution":{"physical_api_request_count":4,"physical_input_tokens":1,"physical_output_tokens":1,"physical_estimated_cost_usd":0}}
    result=build({"sources":sources,"candidates":candidates},snapshot_sha256="a"*64,router=router,selective=selective,calibration=calibration,grounded=grounded,compile_shadow={"aggregate":{}})
    assert result["current_current_head"]["sets"][0]["dataset_kind"]=="synthetic_injected"
    assert result["current_current_head"]["sets"][4]["dataset_kind"]=="commercial_module_case_study"
    assert result["not_measured"]["current_end_to_end_accuracy"] is None
