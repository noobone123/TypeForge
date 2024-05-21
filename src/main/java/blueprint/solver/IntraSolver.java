package blueprint.solver;

import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;

/**
 * Class for intra-procedural analysis
 */
public class IntraSolver {

    private final FunctionNode funcNode;
    private final Context ctx;

    private final PCodeVisitor visitor;

    public IntraSolver(FunctionNode funcNode, Context ctx) {
        // TODO: fix ghidra's function prototype error.
        this.funcNode = funcNode;
        this.ctx = ctx;
        visitor = new PCodeVisitor(this.funcNode, this.ctx);

        /*
         * IMPORTANT: Update the candidate HighSymbols that need to collect data-flow facts
         * Currently, we only collect data-flow facts on :
         * 1. parameters
         * 2. arguments
         * 3. return values
         * and their aliases.
         */
        if (funcNode.parameters.isEmpty()) {
            Logging.warn("No parameters in the function");
        }
        for (var symbol : funcNode.parameters) {
            ctx.addTracedSymbol(funcNode, symbol);
        }
        for (var symbol : funcNode.localVariables) {
            ctx.addTracedSymbol(funcNode, symbol);
        }
        for (var symbol : funcNode.globalVariables) {
            ctx.addTracedSymbol(funcNode, symbol);
        }

        // initialize the data-flow facts
        ctx.initIntraDataFlowFacts(funcNode);
    }


    public void solve() {
        Logging.info("Solving function: " + funcNode.value.getName());

        visitor.prepare();
        visitor.run();

        Logging.info("Solved function: " + funcNode.value.getName());
        ctx.buildConstraints();
        ctx.dumpConstraints(funcNode);
    }

    /**
     * Get the context of the intra-procedural analysis
     * @return The HashMap of HighVariable and TypeBuilder in the function.
     */
    public Context getCtx() {
        return ctx;
    }
}
