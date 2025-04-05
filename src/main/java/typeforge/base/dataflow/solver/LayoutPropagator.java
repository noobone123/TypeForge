package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.dataflow.constraint.Skeleton;
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

        // Step1
        for (var graph: graphManager.getGraphs()) {
            Logging.debug("LayoutPropagator", String.format("*********************** Handle Graph %s ***********************", graph));

            if (!graph.isValid()) {
                Logging.error("LayoutPropagator", String.format("Unexpected Invalid Graph %s, skip it.", graph));
                continue;
            }

            if (graph.getNodes().size() == 1) {
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

        // Reorganize the TFGs
        graphManager.reOrganize();

        // Step2: Now each graph should have only one connected component
        for (var graph: graphManager.getGraphs()) {
            if (!graph.isValid()) {
                Logging.error("TypeHintCollector", String.format("Unexpected Invalid Graph %s, skip it.", graph));
                continue;
            }

            if (graph.getNodes().size() == 1) {
                continue;
            }

            var connectedComponents = graph.getConnectedComponents();
            if (connectedComponents.size() > 1) {
                Logging.error("TypeHintCollector",
                        String.format("Now Each Graph should have only one connected component, but %d", connectedComponents.size()));
                System.exit(1);
            }

            var mergedSkeleton = new Skeleton();
            var connects = connectedComponents.get(0);
            for (var node: connects) {
                var nodeSkt = exprManager.getSkeleton(node);
                if (nodeSkt == null) continue;

                var success = mergedSkeleton.tryMergeLayoutRelax(nodeSkt);
                if (!success) {
                    // IMPORTANT: If not success in merging, means some conflict nodes are not detected by previous propagateLayoutFromSourcesBFS.
                    // This is because if the mergedSkeleton from different source has no intersection in their path, their conflicts will not be detected.
                    // So we need to rebuild the path Manager there and detect them.
                    Logging.error("TypeHintCollector",
                            String.format("Graph: %s -> %d", graph, graph.getNodes().size()));
                    break;
                }
            }
        }
    }
}
