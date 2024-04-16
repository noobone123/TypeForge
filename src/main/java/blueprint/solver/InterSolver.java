package blueprint.solver;

import blueprint.base.CallGraph;
import blueprint.base.FunctionNode;

public class InterSolver {
    CallGraph cg;

    public InterSolver(CallGraph cg) {
        this.cg = cg;
    }


    public void run() {
        // Testing IntraSolver, Starting from specific function
        for (FunctionNode funcNode : cg.functionNodes) {
            if (funcNode.value.getName().equals("array_extend")) {
                IntraSolver intraSolver = new IntraSolver(funcNode);
                intraSolver.solve();
            }
        }
    }
}
