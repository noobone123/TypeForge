package blueprint.solver;

import blueprint.base.CallGraph;
import blueprint.base.FunctionNode;
import blueprint.utils.Logging;

public class InterSolver {
    CallGraph cg;

    public Map<Long, HashMap<>>

    public InterSolver(CallGraph cg) {
        this.cg = cg;
    }


    public void run() {
        // Testing IntraSolver, Starting from specific function
//        for (FunctionNode funcNode : cg.functionNodes) {
//            if (funcNode.value.getName().equals("array_extend")) {
//                IntraSolver intraSolver = new IntraSolver(funcNode);
//                intraSolver.solve();
//            }
//        }

        // network_merge_config_cpv / buffer_truncate / fdevent_sched_close / fdlog_pipes_abandon_pids / config_merge_config_cpv
        // http_response_upgrade_read_body_unknown / mod_scgi_merge_config_cpv / ...
        for (FunctionNode funcNode : cg.leafNodes) {
            if (funcNode.isMeaningful) {
                Logging.info("Leaf node: " + funcNode.value.getName());
            }
        }
    }
}
