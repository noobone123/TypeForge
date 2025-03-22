package typeforge.base.dataflow.solver;

import typeforge.base.node.FunctionNode;
import typeforge.analyzer.PCodeVisitor;
import typeforge.utils.Logging;

/**
 * Class for intra-procedural analysis
 */
public class IntraSolver {

    private final FunctionNode funcNode;
    private final InterSolver interCtx;
    private final IntraContext intraCtx;
    private final PCodeVisitor visitor;

    public IntraSolver(FunctionNode funcNode, InterSolver interCtx, IntraContext intraCtx) {
        this.funcNode = funcNode;
        this.interCtx = interCtx;
        this.intraCtx = intraCtx;
        visitor = new PCodeVisitor(this.funcNode, this.interCtx, this.intraCtx, true);
    }


    public void solve() {
        Logging.info("IntraSolver", "Solving function: " + funcNode.value.getName());

        if (!intraCtx.initialize()) {
            Logging.warn("IntraSolver", "Failed to initialize intraContext: " + funcNode.value.getName());
            return;
        }
        visitor.prepare();
        visitor.run();

        Logging.info("IntraSolver", "Solved function: " + funcNode.value.getName());
    }
}
