package blueprint.solver;

import blueprint.base.dataflow.context.InterContext;
import blueprint.base.dataflow.context.IntraContext;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;

/**
 * Class for intra-procedural analysis
 */
public class IntraSolver {

    private final FunctionNode funcNode;
    private final InterContext interCtx;
    private final IntraContext intraCtx;
    private final PCodeVisitor visitor;

    public IntraSolver(FunctionNode funcNode, InterContext interCtx, IntraContext intraCtx) {
        // TODO: fix ghidra's function prototype error.
        this.funcNode = funcNode;
        this.interCtx = interCtx;
        this.intraCtx = intraCtx;
        visitor = new PCodeVisitor(this.funcNode, this.interCtx, this.intraCtx);

        intraCtx.initialize();
    }


    public void solve() {
        Logging.info("IntraSolver", "Solving function: " + funcNode.value.getName());

        visitor.prepare();
        visitor.run();

        Logging.info("IntraSolver", "Solved function: " + funcNode.value.getName());
    }
}
