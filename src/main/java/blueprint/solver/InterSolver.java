package blueprint.solver;

import blueprint.base.CallGraph;
import blueprint.base.FunctionNode;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import groovy.util.logging.Log;

import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

public class InterSolver {
    CallGraph cg;

    Set<TypeBuilder> allTypes;

    /**
     * Following 2 maps are used to store the relationship between HighVariable and TypeBuilder
     */
    Map<TypeBuilder, Set<HighVariable>> typeToVars;
    Map<HighVariable, TypeBuilder> varToType;

    public InterSolver(CallGraph cg) {
        this.cg = cg;
        allTypes = new HashSet<>();
        typeToVars = new HashMap<>();
        varToType = new HashMap<>();
    }


    public void run() {
        // network_merge_config_cpv / buffer_truncate / fdevent_sched_close / fdlog_pipes_abandon_pids / config_merge_config_cpv
        // http_response_upgrade_read_body_unknown / mod_scgi_merge_config_cpv / ...
        for (FunctionNode funcNode : cg.leafNodes) {
            if (funcNode.isMeaningful) {
                if (funcNode.value.getName().equals("network_merge_config_cpv")) {
                    IntraSolver intraSolver = new IntraSolver(funcNode);
                    intraSolver.solve();
                    // var ctx = intraSolver.getCtx();

                    // Testing redecompile and retype.
                    var dts = DataTypeHelper.getBuiltInLibTypes();
                    for (var dt : dts) {
                        if (dt.getName().equals("uint64_t")) {
                            Logging.info(funcNode.getC());
                            try {
                                HighFunctionDBUtil.updateDBVariable(funcNode.parameters.get(0), null, dt, SourceType.USER_DEFINED);
                                Logging.info("After UpdateDB");
                                Logging.info(funcNode.getC());

                                funcNode.reDecompile();
                                Logging.info("After reDecompile");
                                Logging.info(funcNode.getC());

                            } catch (Exception e) {
                                Logging.error(e.getMessage());
                            }

                            break;
                        }
                    }
                }
            }
        }
    }
}
