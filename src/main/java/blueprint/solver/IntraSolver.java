package blueprint.solver;

import blueprint.base.FunctionNode;
import ghidra.program.model.pcode.HighVariable;

/**
 * Class for intra-procedural analysis
 */
public class IntraSolver {

    private FunctionNode funcNode;

    public IntraSolver(FunctionNode funcNode) {
        this.funcNode = funcNode;
    }

    public void solve() {
        // TODO: Implement intra-procedural analysis
    }


    /**
     * Collect intra-procedural data-flow facts on a parameter or local variable
     */
    private void collectFactsOnVariable(HighVariable highVar) {
        // TODO:
    }
}
