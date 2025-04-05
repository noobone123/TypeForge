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
        for (var graph: graphManager.getGraphs()) {
            Logging.debug("LayoutPropagator", String.format("*********************** Handle Graph %s ***********************", graph));

            if (!graph.isValid()) {
                Logging.error("LayoutPropagator", String.format("Unexpected Invalid Graph %s, skip it.", graph));
                continue;
            }

            if (graph.getNodes().size() == 1) {
                Logging.debug("LayoutPropagator", String.format("Graph %s has only one node, skip it.", graph));
                continue;
            }

            graph.pathManager.initialize();
            graph.pathManager.tryMergeLayoutFormSamePathsForward(exprManager);
            graph.pathManager.tryMergeLayoutFromSameSourceForward(exprManager);

            // Removing Evil Edges in layout information aggregate
            // These edges including alias edges.
            for (var edge: graph.pathManager.evilEdgesInPerPath) {
                graph.removeEdge(graph.getGraph().getEdgeSource(edge), graph.getGraph().getEdgeTarget(edge));
            }
            for (var edge: graph.pathManager.evilEdgesInSourceAggregate) {
                graph.removeEdge(graph.getGraph().getEdgeSource(edge), graph.getGraph().getEdgeTarget(edge));
            }
            /* Backward edges must be removed before BFS,
                as the previous merge was based on TFGPath,
                and the subsequent BFS will not involve path. */
            for (var edge: graph.pathManager.backwardEdges) {
                graph.removeEdge(graph.getGraph().getEdgeSource(edge), graph.getGraph().getEdgeTarget(edge));
            }

            graph.pathManager.propagateLayoutFromSourcesBFS();
        }

        graphManager.reOrganize();
    }
}
