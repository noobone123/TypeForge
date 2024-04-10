package blueprint.solver;

import blueprint.base.FunctionNode;
import blueprint.utils.Logging;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import groovy.util.logging.Log;

/**
 * Class for intra-procedural analysis
 */
public class IntraSolver {

    private final FunctionNode funcNode;

    public IntraSolver(FunctionNode funcNode) {
        this.funcNode = funcNode;
    }

    public void solve() {
        Logging.info("Solving function: " + funcNode.value.getName());

        if (funcNode.parameters.isEmpty()) {
            Logging.warn("No parameters in the function");
        }

        Logging.info("Parameters Count: " + funcNode.parameters.size());
        for (var param : funcNode.parameters) {
            collectFactsOnParameter(param);
        }
    }

    /**
     * Collect intra-procedural data-flow facts on a parameter or local variable
     */
    private void collectFactsOnParameter(HighSymbol highSym) {
        HighVariable highVar = highSym.getHighVariable();
        Logging.info("HighSymbol: " + highSym);
        Logging.info("HighVariable: " + highVar);

        var startVarNode = highVar.getRepresentative();
        Logging.info("StartVarNode: " + startVarNode);

        for (var instance : highVar.getInstances()) {
            Logging.info("Instance: " + instance);
        }



    }
}
