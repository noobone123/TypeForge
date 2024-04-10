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

        for (var param : funcNode.parameters) {
            collectFactsOnParameter(param);
        }
    }


    /**
     * Collect intra-procedural data-flow facts on a parameter or local variable
     */
    private void collectFactsOnParameter(HighSymbol highVar) {
        Logging.info("HighSymbol: " + highVar.getName());
    }
}
