package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.utils.Logging;

import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

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
        // Step1: process all the TFGs in the first pass
        processAllGraphsFirstPass();

        // Reorganize the TFGs
        graphManager.reOrganize();

        // Step2: process the conflict graphs in the workList
        processConflictGraphs();
    }

    private void processConflictGraphs() {
        // Step2: iteratively process the conflict graphs in the workList
        Queue<TypeFlowGraph<NMAE>> workList = new LinkedList<>();

        for (var graph: graphManager.getGraphs()) {
            if (!graphManager.isProcessableGraph(graph)) {
                continue;
            }
            addToWorkListIfConflict(workList, graph);
        }

        while (!workList.isEmpty()) {
            TypeFlowGraph<NMAE> graph = workList.poll();

            graph.pathManager.initialize();
            var hasPathMergeConflict = graph.pathManager.tryMergeLayoutFormSamePathsForward(exprManager);
            var hasSourceMergeConflict = graph.pathManager.tryMergeLayoutFromSameSourceForward(exprManager);
            if (hasPathMergeConflict || hasSourceMergeConflict) {
                Logging.error("LayoutPropagator",
                        "Should not have any merge conflict after the first pass in theory, please check the code.");
            }
            // Following Propagation is actually not needed
            var hasBFSConflict = graph.pathManager.propagateLayoutFromSourcesBFS();
            if (hasBFSConflict) {
                Logging.error("LayoutPropagator",
                        "Should not have any BFS conflict after the first pass in theory, please check the code.");
            }

            graph.pathManager.resolveMultiSourceConflicts();
            /* remember to remove the evil edges related to Multi Source Conflicts */
            for (var edge: graph.pathManager.evilEdgesInMultiSourceResolving) {
                graph.removeEdge(graph.getGraph().getEdgeSource(edge), graph.getGraph().getEdgeTarget(edge));
            }

            var newGraphs = graphManager.reOrganizeTFG(graph);
            for (var newGraph: newGraphs) {
                if (!graphManager.isProcessableGraph(newGraph)) {
                    continue;
                }
                addToWorkListIfConflict(workList, newGraph);
            }
        }
    }

    private void processAllGraphsFirstPass() {
        // Step1
        for (var graph: graphManager.getGraphs()) {
            Logging.debug("LayoutPropagator", String.format("*********************** Handle Graph %s ***********************", graph));

            if (!graphManager.isProcessableGraph(graph)) {
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

            /* remember to remove the evil edges related to BFS */
            for (var edge: graph.pathManager.evilEdgesInPropagateBFS) {
                graph.removeEdge(graph.getGraph().getEdgeSource(edge), graph.getGraph().getEdgeTarget(edge));
            }
        }
    }

    private void addToWorkListIfConflict(Queue<TypeFlowGraph<NMAE>> workList, TypeFlowGraph<NMAE> graph) {
        var connectedComponents = graph.getConnectedComponents();
        if (connectedComponents.size() > 1) {
            Logging.error("LayoutPropagator",
                    String.format("Now Each Graph should have only one connected component, but %d", connectedComponents.size()));
            System.exit(1);
        }

        var connects = connectedComponents.get(0);
        var success = graphManager.tryToMergeAllNodesSkeleton(graph, connects, exprManager);
        // IMPORTANT: If not success in merging, means some conflict nodes are not detected by previous propagateLayoutFromSourcesBFS.
        // This is because if the mergedSkeleton from different source has no intersection in their path, their conflicts will not be detected.
        // So we need to rebuild the path Manager there and detect them.
        if (!success) {
            workList.add(graph);
            Logging.info("LayoutPropagator",
                    String.format("Graph: %s (%d) has been added into work list ...", graph, connects.size()));
        }
    }
}
