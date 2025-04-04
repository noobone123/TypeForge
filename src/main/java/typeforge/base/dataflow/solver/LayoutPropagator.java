package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.utils.Logging;

/**
 * Used for propagating Layout information through the whole-program TFG and
 * further find the evil edges.
 */
public class LayoutPropagator {

    InterSolver interSolver;
    NMAEManager exprManager;
    TFGManager graphManager;

    public LayoutPropagator(InterSolver interSolver) {
        this.interSolver = interSolver;
        this.exprManager = interSolver.exprManager;
        this.graphManager = interSolver.graphManager;
    }

    public void run() {
        graphManager.initAllPathManagers();
        for (var graph: graphManager.getGraphs()) {
            if (graph.pathManager.hasSrcSink) {
                Logging.debug("LayoutPropagator", String.format("*********************** Handle Graph %s ***********************", graph));
                graph.pathManager.tryMergeLayoutFormSamePaths(exprManager);
                graph.pathManager.tryMergeLayoutFromSameSource(exprManager);

                // Removing Evil Edges in layout information aggregate
                // These edges including alias edges.
                var evilEdgesInPerPath = graph.pathManager.evilEdgesInPerPath;
                var evilEdgesInSourceAggregate = graph.pathManager.evilEdgesInSourceAggregate;
                for (var edge: evilEdgesInPerPath) {
                    graph.removeEdge(graph.getGraph().getEdgeSource(edge), graph.getGraph().getEdgeTarget(edge));
                }
                for (var edge: evilEdgesInSourceAggregate) {
                    graph.removeEdge(graph.getGraph().getEdgeSource(edge), graph.getGraph().getEdgeTarget(edge));
                }

                // Propagate the aggregated layout information to the whole-program TFG by BFS
                graph.pathManager.propagateLayoutFromSourcesBFS();
            }
        }
    }
}
