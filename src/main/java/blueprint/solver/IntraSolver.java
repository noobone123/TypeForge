package blueprint.solver;

import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;

import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;

import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

/**
 * Class for intra-procedural analysis
 */
public class IntraSolver {

    private final FunctionNode funcNode;
    private final Context ctx;

    /** The candidate HighSymbols that need to collect data-flow facts */
    private final List<HighSymbol> candidates;

    private final PCodeVisitor visitor;

    public IntraSolver(FunctionNode funcNode, Context ctx) {
        // TODO: fix ghidra's function prototype error.
        this.funcNode = funcNode;
        if (ctx == null) {
            this.ctx = new Context();
        } else {
            this.ctx = ctx;
        }
        this.candidates = new LinkedList<>();
        visitor = new PCodeVisitor(this.funcNode, this.ctx);
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

        visitor.prepare(candidates);
        visitor.run();
        visitor.updateContext();

        ctx.dump();
    }

    /**
     * Get the context of the intra-procedural analysis
     * @return The HashMap of HighVariable and TypeBuilder in the function.
     */
    public Context getCtx() {
        return ctx;
    }
}
