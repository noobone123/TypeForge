package blueprint.solver;

import blueprint.base.FunctionNode;
import blueprint.utils.Logging;
import blueprint.solver.TypeBuilder;

import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;

import java.util.HashMap;

/**
 * Class for intra-procedural analysis
 */
public class IntraSolver {

    private final FunctionNode funcNode;
    private final Context ctx;

    public IntraSolver(FunctionNode funcNode, Context ctx) {
        this.funcNode = funcNode;
        if (ctx == null) {
            this.ctx = new Context();
        } else {
            this.ctx = ctx;
        }
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
     * Get the context of the intra-procedural analysis
     * @return The HashMap of HighVariable and TypeBuilder in the function.
     */
    public Context getCtx() {
        return ctx;
    }


    /**
     * Collect intra-procedural data-flow facts on a parameter or local variable
     * This Analysis is an on-demand analysis, because we only collect facts on
     * Parameters / Variables we are interested in.
     * @param highSym the HighSymbol to collect facts on
     */
    private void collectFactsOnParameter(HighSymbol highSym) {
        // TODO: fix ghidra's function prototype error.
        HighVariable highVar = highSym.getHighVariable();
        Logging.info("HighSymbol: " + highSym.getName());

        // If a HighSymbol (like a parameter) is not be used in the function, it can not hold a HighVariable
        if (highVar == null) {
            Logging.warn(funcNode.value.getName() + " -> HighSymbol: " + highSym.getName() + " has no HighVariable");
            return;
        }

        // Collect dataflow-facts from specific VarNode
        PCodeVisitor visitor = new PCodeVisitor(highVar, ctx);
        visitor.run();
    }
}
