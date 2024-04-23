package blueprint.solver;

import blueprint.base.FunctionNode;
import blueprint.utils.Logging;

import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;

import java.util.LinkedList;
import java.util.Queue;

/**
 * Class for intra-procedural analysis
 */
public class IntraSolver {

    private final FunctionNode funcNode;
    private final Context ctx;

    /** The candidate HighSymbols that need to collect data-flow facts */
    private final Queue<HighSymbol> candidates;

    public IntraSolver(FunctionNode funcNode, Context ctx) {
        // TODO: fix ghidra's function prototype error.
        this.funcNode = funcNode;
        if (ctx == null) {
            this.ctx = new Context();
        } else {
            this.ctx = ctx;
        }
        this.candidates = new LinkedList<>();
        updateCandidates();
    }

    /**
     * IMPORTANT: Update the candidate HighSymbols that need to collect data-flow facts
     * Currently, we only collect data-flow facts on parameters and symbols used as arguments at callsite.
     */
    public void updateCandidates() {
        if (funcNode.parameters.isEmpty()) {
            Logging.warn("No parameters in the function");
        }
        candidates.addAll(funcNode.parameters);

        // If it has highSymbols merged from callee functions
        if (!ctx.isEmpty()) {
            for (var symbol : ctx.getHighSymbols()) {
                if (funcNode.parameters.contains(symbol)) {
                    continue;
                }
                candidates.add(symbol);
            }
        }
    }


    public void solve() {
        Logging.info("Solving function: " + funcNode.value.getName());

        for (var symbol : candidates) {
            collectFactsOnSymbol(symbol);
        }

        ctx.dump();
    }

    /**
     * Collect intra-procedural data-flow facts on a highSymbol (parameter or local variable)
     * This Analysis is an on-demand analysis, because we only collect facts on
     * Parameters / Variables we are interested in.
     * @param highSym the HighSymbol to collect facts on
     */
    private void collectFactsOnSymbol(HighSymbol highSym) {
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


    /**
     * Get the context of the intra-procedural analysis
     * @return The HashMap of HighVariable and TypeBuilder in the function.
     */
    public Context getCtx() {
        return ctx;
    }
}
