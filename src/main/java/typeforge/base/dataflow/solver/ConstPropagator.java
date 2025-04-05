package typeforge.base.dataflow.solver;

import generic.stl.Pair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.dataflow.constraint.SizeSource;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.node.CallSite;
import typeforge.base.node.FunctionNode;
import typeforge.utils.Logging;

import java.util.*;

/**
 * There are many constants in the TFG, such as: malloc(0x10), memset(0x20), and sizes in built MMAE's skeletons.
 * These constants are useful for us to identify the size conflicts in the TFG, which always involve union/typecasting.
 *
 * This Simple Constant Propagator is used to :
 * 1. Propagate the constant arguments and check if they can propagate to the sensitive function's arguments.
 *    If so, we need update related skeletons.
 *      For example, if
 *         1. const_arg_1 -> wrapper_func_param1 -> malloc(sink_arg)
 *         2. const_arg_2 -> wrapper_func_param1 -> malloc(sink_arg)
 *         And there's also a path from malloc's return value to corresponding callsite's reciver
 *      Then this receiver's skeleton's size should be set.
 *      And the wrapper function should also be identified and marked.
 *
 *  2. Propagate the skeleton's size info on the TFG and marking the size conflict.
 */
public class ConstPropagator {

    /**
     * Allocation type for malloc/calloc/...
     */
    enum AllocType {
        MALLOC,
        CALLOC
    }

    enum ConstType {
        MALLOC_SIZE,
        CALLOC_NITEMS,
        CALLOC_SIZE,
    }

    /**
     * WrapperCallSiteInfo is used to store the information of wrapper call sites,
     * particularly for important size constants about malloc/calloc.
     */
    static class WrapperCallSiteInfo {
        public CallSite callSite;
        public AllocType allocType;

        public long mallocSize;
        public long callocNitems;
        public long callocSize;

        Set<NMAE> constArgs;

        public WrapperCallSiteInfo(CallSite callSite, AllocType allocType) {
            this.callSite = callSite;
            this.allocType = allocType;
            this.constArgs = new HashSet<>();
        }

        public WrapperCallSiteInfo(CallSite callSite, AllocType allocType, long callocNitems, long callocSize) {
            this.callSite = callSite;
            this.allocType = allocType;
            this.callocNitems = callocNitems;
            this.callocSize = callocSize;
            this.constArgs = new HashSet<>();
        }

        public void updateConstArgs(NMAE constArg) {
            this.constArgs.add(constArg);
        }

        public Set<NMAE> getConstArgs() {
            return this.constArgs;
        }

        public void updateMallocSizeInformation(long size) {
            this.mallocSize = size;
        }

        public void updateCallocNitemsInformation(long nitems) {
            this.callocNitems = nitems;
        }

        public void updateCallocSizeInformation(long size) {
            this.callocSize = size;
        }

        public long getSize() {
            if (allocType == AllocType.MALLOC) {
                return this.mallocSize;
            } else if (allocType == AllocType.CALLOC) {
                return this.callocNitems * this.callocSize;
            }
            return 0;
        }
    }

    InterSolver interSolver = null;
    NMAEManager exprManager;
    TFGManager graphManager;

    Set<FunctionNode> wrapperFunctions;
    Set<Pair<NMAE, NMAE>> wrapperEvilEdges;
    Set<NMAE> unionEvilNodes;
    Set<Pair<NMAE, NMAE>> unionEvilEdges;
    Set<NMAE> sizeConflictNodes;

    // By checking connected node's skeleton, size and layout information can be obtained.
    Set<Pair<NMAE, NMAE>> sizeConflictEvilEdges;

    public ConstPropagator(InterSolver interSolver) {
        this.interSolver = interSolver;
        this.exprManager = this.interSolver.exprManager;
        this.graphManager = this.interSolver.graphManager;

        wrapperFunctions = new HashSet<>();
        wrapperEvilEdges = new HashSet<>();

        unionEvilNodes = new HashSet<>();
        unionEvilEdges = new HashSet<>();

        sizeConflictNodes = new HashSet<>();
        sizeConflictEvilEdges = new HashSet<>();
    }

    public void run() {
        markWrapperFunctionAndSize();
        removeEvilEdgesInWrapper();
        handleMultiSizeSources();
        removeEvilEdgesInUnions();

        sizeConstantPropagation();

        Logging.info("ConstPropagator",
                String.format("There are total %d wrapper functions", wrapperFunctions.size()));
        for (var wrapper: wrapperFunctions) {
            Logging.info("ConstPropagator",
                    String.format("Wrapper Function: %s", wrapper.value.getName()));
        }

        Logging.info("ConstPropagator",
                String.format("There are total %d confirmed union nodes", unionEvilNodes.size()));
        Logging.info("ConstPropagator",
                String.format("There are total %d union evil edges", unionEvilEdges.size()));
        for (var union: unionEvilNodes) {
            Logging.info("ConstPropagator",
                    String.format("Union Node: %s", union));
        }

        Logging.info("ConstPropagator",
                String.format("There are total %d size conflict nodes", sizeConflictNodes.size()));
        Logging.info("ConstPropagator",
                String.format("There are total %d size conflict evil edges", sizeConflictEvilEdges.size()));
        for (var node: sizeConflictNodes) {
            Logging.info("ConstPropagator",
                    String.format("Size Conflict Node: %s", node));
        }

        // Since some edges are removed during the Const Propagate, so we need to re-organize the whole-program TFG
        // Maybe not necessary, but it's elegance to do so. (however, it may cause some performance issue)
        graphManager.reOrganize();
    }

    /**
     * After all size information of skeletons is collected, we can propagate the size information along the TFG forward.
     * And detect then mark the size conflicts.
     */
    private void sizeConstantPropagation() {
        // 1st: Get all propagated sources
        Map<NMAE, Skeleton> propagatedSources = new HashMap<>();
        for (var entry: exprManager.getExprToSkeletonBeforeMerge().entrySet()) {
            var expr = entry.getKey();
            if (unionEvilNodes.contains(expr)) {
                continue;
            }

            var skt = entry.getValue();
            if (skt.hasSizeSource()) {
                if (skt.getSizeSources().size() > 1) {
                    Logging.warn("ConstPropagator",
                            String.format("Skeleton of %s has multiple size sources: %s", expr, skt.getSizeSources()));
                } else {
                    propagatedSources.put(expr, skt);
                }
            }
        }
        Logging.debug("ConstPropagator",
                String.format("There are total %d sources with size information ready to propagate.", propagatedSources.size()));

        // 2nd: Propagate size information forward and backward along the dataflow/call/return edges in the TFG
        doPropagateBFSOnTFG(propagatedSources, true);
        doPropagateBFSOnTFG(propagatedSources, false);

        // Simple statistics
        for (var node: sizeConflictNodes) {
            var skt = exprManager.getOrCreateSkeleton(node);
            if (!skt.hasMultiSizeSource()) {
                Logging.warn("ConstPropagator", "Unexpected: Size Conflict Node has no multi size source");
            }
            var sizeSources = skt.getSizeSources();
            Logging.debug("ConstPropagator",
                    String.format("Size sources: %s", sizeSources));
        }

        // 3rd: Remove "evil edges" related to these conflict nodes.
        // These conflict nodes typically account for no more than 1%, and it is worthwhile to remove their edges to prevent the propagation of errors in the data flow.
        for (var node: sizeConflictNodes) {
            var removedEdges = graphManager.removeAllEdgesOfNode(node);
            sizeConflictEvilEdges.addAll(removedEdges);
        }
    }

    /**
     * Find and mark alloc wrapper functions in the program,
     * then calculate the allocated size information and set these size to the skeletons.
     */
    private void markWrapperFunctionAndSize() {
        // Process malloc call sites
        processMallocWrapperAndSize();
        // Process calloc call sites
        processCallocWrapperAndSize();

        for (var wrapperFunc: wrapperFunctions) {
            Logging.info("ConstPropagator",
                    String.format("Found Wrapper Function %s", wrapperFunc.value.getName()));
        }
    }

    /**
     * The edge between the wrapper function's return NMAE and the receiver NMAE is evil.
     * Should be marked as evil and removed.
     */
    private void removeEvilEdgesInWrapper() {
        // Found EvilEdges
        for (var wrapper: wrapperFunctions) {
            var wrapperRetExpr = interSolver.intraSolverMap.get(wrapper.value).getReturnExpr();
            var wrapperCSs = interSolver.calleeToCallSites.get(wrapper);
            for (var wrapperCS: wrapperCSs) {
                var wrapperCSReceiver = wrapperCS.receiver;
                var wrapperCSReceiverExpr = interSolver.intraSolverMap.get(wrapperCS.caller)
                        .getOrCreateDataFlowFacts(wrapperCSReceiver);
                for (var expr1: wrapperRetExpr) {
                    for (var expr2: wrapperCSReceiverExpr) {
                        if (graphManager.hasDataFlowPath(expr1, expr2)) {
                            // Mark the edge as evil
                            wrapperEvilEdges.add(
                                    new Pair<>(expr1, expr2) // wrapperRetExpr -> wrapperCSReceiverExpr
                            );
                            Logging.debug("ConstPropagator",
                                    String.format("Found Evil Edge %s -> %s", expr1, expr2));
                        }
                    }
                }
            }
        }

        // Remove EvilEdges
        for (var pair: wrapperEvilEdges) {
            var from = pair.first;
            var to = pair.second;
            graphManager.removeEdge(from, to);
        }
    }

    /**
     * Some skeletons may have different sizes before ConstantPropagation.
     * We need to ensure that there are only one reliable size used for constant propagation.
     * <br>
     * Some Obvious unions are also identified in this step.
     */
    private void handleMultiSizeSources() {
        int sktWithSizeCount = 0;
        int sktWithMultiSizeCount = 0;
        for (var expr: exprManager.getExprToSkeletonBeforeMerge().keySet()) {
            var skt = exprManager.getSkeleton(expr);
            if (skt.hasSizeSource()) {
                sktWithSizeCount++;
            }

            if (skt.hasMultiSizeSource()) {
                var sizeSources = skt.getSizeSources();
                var sizeSourceFromExprs = new HashSet<SizeSource>();
                var sizeSourceFromCallSites = new HashSet<SizeSource>();

                for (var sizeSource: sizeSources) {
                    if (sizeSource.getSourceType() == SizeSource.SourceType.EXPRESSION) {
                        sizeSourceFromExprs.add(sizeSource);
                    } else if (sizeSource.getSourceType() == SizeSource.SourceType.CALLSITE) {
                        sizeSourceFromCallSites.add(sizeSource);
                    }
                }

                // IMPORTANT: We need to ensure there are only one size used for constant propagation.
                var sizeFromExprs = new HashSet<Long>();
                var sizeFromCallSites = new HashSet<Long>();
                for (var sizeSource: sizeSourceFromExprs) {
                    sizeFromExprs.add(sizeSource.getSize());
                }
                for (var sizeSource: sizeSourceFromCallSites) {
                    sizeFromCallSites.add(sizeSource.getSize());
                }

                // If stack allocated expr, its decompiler inferred size should be omitted as decompiler-inferred
                // size is always not reliable, so we choose to believe the size from callSite.
                var isStackAllocated = expr.isReference();
                if (isStackAllocated && !sizeFromCallSites.isEmpty()) {
                    sizeSources = sizeSourceFromCallSites;
                }

                // If there's only one size from exprs and one size from call sites,
                // we choose the larger one for final size.
                // sizeFromExprs's max size should be 1.
                if (!isStackAllocated && sizeFromExprs.size() == 1 && sizeFromCallSites.size() == 1) {
                    var sizeFromExpr = sizeFromExprs.iterator().next();
                    var sizeFromCallSite = sizeFromCallSites.iterator().next();
                    if (sizeFromExpr > sizeFromCallSite) {
                        sizeSources = sizeSourceFromExprs;
                    } else {
                        sizeSources = sizeSourceFromCallSites;
                    }
                }

                var consideredSizes = new HashSet<Long>();
                for (var sizeSource: sizeSources) {
                    consideredSizes.add(sizeSource.getSize());
                }

                // These are union.
                if (consideredSizes.size() > 1) {
                    sktWithMultiSizeCount++;
                    unionEvilNodes.add(expr);
                    Logging.debug("ConstPropagator",
                            String.format("Found Union Expr %s with multiple SizeSource: %s", expr, sizeSources));
                } else {
                    var sizeSource = sizeSources.iterator().next();
                    exprManager.getSkeleton(expr).strongUpdateSizeSources(sizeSource);
                    Logging.debug("ConstPropagator",
                            String.format("Set Final SizeSource for Expr %s -> %s", expr, sizeSource));
                }
            }
        }

        Logging.info("ConstPropagator",
                String.format("Found %d skeletons with size, %d skeletons with multiple sizes", sktWithSizeCount, sktWithMultiSizeCount));
    }

    private void removeEvilEdgesInUnions() {
        for (var expr: unionEvilNodes) {
            var removedEdges = graphManager.removeAllEdgesOfNode(expr);
            unionEvilEdges.addAll(removedEdges);
        }
    }

    private void processMallocWrapperAndSize() {
        for (var cs : interSolver.mallocCs) {
            if (cs.arguments.isEmpty()) continue;

            var sensitiveArg = cs.arguments.get(0);

            // Skip direct calls with constant arguments
            if (sensitiveArg.isConstant()) {
                Logging.debug("ConstPropagator",
                        String.format("Found malloc with constant argument: %s, skip", cs));
                continue;
            }


            // Find wrapper call sites and update receivers
            Set<NMAE> reachableNodes = findReachableNodes(sensitiveArg, cs.caller);
            var mayWrapperCSInfo = markPossibleWrapperCS(reachableNodes, AllocType.MALLOC, ConstType.MALLOC_SIZE);
            var finalWrapperCSInfo = confirmWrapperCallSites(mayWrapperCSInfo, cs);
            updateReceivers(finalWrapperCSInfo);
        }
    }

    private void processCallocWrapperAndSize() {
        for (var cs : interSolver.callocCs) {
            if (cs.arguments.size() < 2) continue;

            var countArg = cs.arguments.get(0);
            var sizeArg = cs.arguments.get(1);

            // Skip direct calls with constant arguments
            if (countArg.isConstant() && sizeArg.isConstant()) {
                Logging.debug("ConstPropagator",
                        String.format("Found calloc with constant arguments: %s, skip", cs));
                continue;
            }

            // Find common wrapper call sites for both arguments
            Set<NMAE> reachableNodesCount = findReachableNodes(countArg, cs.caller);
            Set<NMAE> reachableNodesSize = findReachableNodes(sizeArg, cs.caller);

            var mayWrapperCSInfoCount = markPossibleWrapperCS(reachableNodesCount, AllocType.CALLOC, ConstType.CALLOC_NITEMS);
            var mayWrapperCSInfoSize = markPossibleWrapperCS(reachableNodesSize, AllocType.CALLOC, ConstType.CALLOC_SIZE);

            var mayWrapperCSInfo = mergeCallocWrapperCSInfo(mayWrapperCSInfoCount, mayWrapperCSInfoSize);
            var finalWrapperCSInfo = confirmWrapperCallSites(mayWrapperCSInfo, cs);
            updateReceivers(finalWrapperCSInfo);
        }
    }

    private Set<NMAE> findReachableNodes(Varnode sensitiveArg, Function callSiteFunc) {
        var intraSolver = interSolver.intraSolverMap.get(callSiteFunc);
        var reachableNodes = new HashSet<NMAE>();

        for (var sensitiveExpr : intraSolver.getOrCreateDataFlowFacts(sensitiveArg)) {
            var result = interSolver.graphManager.findReachableNodes(sensitiveExpr, 10);
            Logging.debug("ConstPropagator",
                    String.format("Size of reachable nodes to %s: %d", sensitiveExpr, result.size()));
            reachableNodes.addAll(result);
        }

        return reachableNodes;
    }

    /**
     * Mark possible wrapper call sites based on the reachable nodes and their allocation types.
     * also update important constant information for malloc/calloc.
     */
    private Map<CallSite, WrapperCallSiteInfo>
        markPossibleWrapperCS(Set<NMAE> reachableNodes, AllocType allocType, ConstType constType) {

        Map<CallSite, WrapperCallSiteInfo> mayWrapperCSInfoMap = new HashMap<>();

        for (var node : reachableNodes) {
            if (node.isConstArg()) {
                var wrapperCS = node.getCallSite();
                var wrapperCSInfo = mayWrapperCSInfoMap.computeIfAbsent(wrapperCS,
                        cs -> new WrapperCallSiteInfo(cs, allocType));

                wrapperCSInfo.updateConstArgs(node);
                if (allocType == AllocType.MALLOC) {
                    wrapperCSInfo.updateMallocSizeInformation(node.getConstant());
                    Logging.debug("ConstPropagator",
                            String.format("Found Arg Const which can flow to Malloc's size: %s", node));
                } else if (allocType == AllocType.CALLOC) {
                    if (constType == ConstType.CALLOC_NITEMS) {
                        wrapperCSInfo.updateCallocNitemsInformation(node.getConstant());
                        Logging.debug("ConstPropagator",
                                String.format("Found Arg Const which can flow to Calloc's nitems: %s", node));
                    } else if (constType == ConstType.CALLOC_SIZE) {
                        wrapperCSInfo.updateCallocSizeInformation(node.getConstant());
                        Logging.debug("ConstPropagator",
                                String.format("Found Arg Const which can flow to Calloc's size: %s", node));
                    }
                }
            }
        }

        return mayWrapperCSInfoMap;
    }

    private Map<CallSite, WrapperCallSiteInfo> confirmWrapperCallSites(
            Map<CallSite, WrapperCallSiteInfo> mayWrapperCSInfo,
            CallSite allocCS
    ) {
        Map<CallSite, WrapperCallSiteInfo> newWrapperCSInfoMap = new HashMap<>();
        var graphManager = interSolver.graphManager;
        var intraSolverMap = interSolver.intraSolverMap;

        for (var callsite: mayWrapperCSInfo.keySet()) {
            var wrapperCSReceiver = callsite.receiver;
            var receiverFacts = intraSolverMap.get(callsite.caller)
                    .getOrCreateDataFlowFacts(wrapperCSReceiver);
            var sensitiveRetFacts = intraSolverMap.get(allocCS.caller)
                    .getOrCreateDataFlowFacts(allocCS.receiver);

            boolean hasPath = false;
            for (var from : sensitiveRetFacts) {
                for (var to : receiverFacts) {
                    // If reachable, confirmed
                    if (graphManager.hasDataFlowPath(from, to)) {
                        // Mark and Confirm Wrapper Functions.
                        wrapperFunctions.add(interSolver.callGraph.getNodebyAddr(callsite.calleeAddr));

                        // Update the wrapper call site info
                        newWrapperCSInfoMap.put(callsite, mayWrapperCSInfo.get(callsite));
                        var callee = interSolver.callGraph.getNodebyAddr(callsite.calleeAddr);
                        Logging.debug("ConstPropagator",
                                String.format("Found Wrapper Function %s called by %s with size: 0x%x",
                                        callee.value.getName(),
                                        callsite,
                                        newWrapperCSInfoMap.get(callsite).getSize()));
                        hasPath = true;
                        break;
                    }
                }
                if (hasPath) break;
            }
        }

        // Print mayWrapperCSInfo - newWrapperCSInfoMap
        // As Ghidra may miss some dataflow edges due to tail call, some not all Wrapper Function call be successfully identified.
        var temp = new HashSet<>(mayWrapperCSInfo.keySet());
        temp.removeAll(newWrapperCSInfoMap.keySet());
        for (var callsite : temp) {
            Logging.trace("ConstPropagator",
                    String.format("Found Wrapper Function %s, but not confirmed", callsite));
        }

        return newWrapperCSInfoMap;
    }


    private Map<CallSite, WrapperCallSiteInfo> mergeCallocWrapperCSInfo(
            Map<CallSite, WrapperCallSiteInfo> mayWrapperCSInfoCount,
            Map<CallSite, WrapperCallSiteInfo> mayWrapperCSInfoSize
    ) {
        Map<CallSite, WrapperCallSiteInfo> mergedMap = new HashMap<>();
        // Key: CallSite should exist in both maps
        for (var entry : mayWrapperCSInfoCount.entrySet()) {
            var callSite = entry.getKey();
            if (mayWrapperCSInfoSize.containsKey(callSite)) {
                var wrapperCSInfoCount = entry.getValue();
                var wrapperCSInfoSize = mayWrapperCSInfoSize.get(callSite);
                var newWrapperCSInfo = new WrapperCallSiteInfo(
                        callSite,
                        AllocType.CALLOC,
                        wrapperCSInfoCount.callocNitems,
                        wrapperCSInfoSize.callocSize
                );
                newWrapperCSInfo.constArgs.addAll(wrapperCSInfoCount.constArgs);
                newWrapperCSInfo.constArgs.addAll(wrapperCSInfoSize.constArgs);

                mergedMap.put(callSite, newWrapperCSInfo);
            }
        }
        return mergedMap;
    }


    private void updateReceivers(Map<CallSite, WrapperCallSiteInfo> finalWrapperCSInfo) {
        for (var entry: finalWrapperCSInfo.entrySet()) {
            var callSite = entry.getKey();
            var wrapperCSInfo = entry.getValue();
            var receiver = callSite.receiver;
            var receiverFacts = interSolver.intraSolverMap.get(callSite.caller)
                    .getOrCreateDataFlowFacts(receiver);
            for (var expr: receiverFacts) {
                var skt = this.exprManager.getOrCreateSkeleton(expr);
                skt.setComposite(true);
                skt.setSizeFromCallSite(wrapperCSInfo.getSize(), callSite);
            }
        }
    }


    /**
     * Propagate size information in BFS on the TFG, propagate should start from each source in each round.
     *
     * @param propagatedSources the sources to propagate
     * @param forward if true, propagate forward, otherwise backward
     */
    private void doPropagateBFSOnTFG(Map<NMAE, Skeleton> propagatedSources, boolean forward) {
        // When propagating, the information may be propagated to multiple nodes, and forming a
        // continuously expanding region. So we need to keep track of the source nodes and their
        // border nodes to do next round of BFS propagation.
        Map<NMAE, Set<NMAE>> sourceToBorderNodes = new HashMap<>();
        // initial border nodes are the source nodes itself
        for (var expr: propagatedSources.keySet()) {
            var borderNodes = new HashSet<NMAE>();
            borderNodes.add(expr);
            sourceToBorderNodes.put(expr, borderNodes);
        }

        // Used to recording the propagated nodes from each source node,
        // avoid repeating propagate to the same node for each source.
        Map<NMAE, Set<NMAE>> sourceToPropagatedNodes = new HashMap<>();
        for (var expr: propagatedSources.keySet()) {
            sourceToPropagatedNodes.put(expr, new HashSet<>());
            sourceToPropagatedNodes.get(expr).add(expr);
        }

        // Process sources in a deterministic order
        List<NMAE> sortedSources = new ArrayList<>(propagatedSources.keySet());
        sortedSources.sort(Comparator.comparing(NMAE::hashCode));

        boolean hasNewBorderNode = true;
        // If no new border node can be found, we stop the propagation.
        while (hasNewBorderNode) {
            hasNewBorderNode = false;

            // Each round, propagate size information from each source.
            for (var source: sortedSources) {
                var sourceSkt = propagatedSources.get(source);
                var sourceSizeInfo = sourceSkt.getSizeSources().iterator().next();
                var currentBorderNodes = sourceToBorderNodes.get(source);
                var newBorderNodes = new HashSet<NMAE>();

                // For each border node, propagate the size information to its neighbors.
                // And finally update the border.
                List<NMAE> sortedBorderNodes = new ArrayList<>(currentBorderNodes);
                sortedBorderNodes.sort(Comparator.comparing(NMAE::hashCode));
                for (var borderNode: sortedBorderNodes) {
                    // IMPORTANT: SizeConflictNodes should not be seen as border nodes.
                    if (sizeConflictNodes.contains(borderNode)) continue;

                    Set<NMAE> neighbors = new HashSet<>();
                    if (forward) {
                        neighbors.addAll(graphManager.getForwardNeighbors(borderNode));
                    } else {
                        neighbors.addAll(graphManager.getBackwardNeighbors(borderNode));
                    }

                    // Propagate to each neighbor of current border node
                    List<NMAE> sortedNeighbors = new ArrayList<>(neighbors);
                    sortedNeighbors.sort(Comparator.comparing(NMAE::hashCode));
                    for (var neighbor: sortedNeighbors) {
                        // If the neighbor is already propagated from the source, just continue
                        if (sourceToPropagatedNodes.get(source).contains(neighbor)) continue;

                        var neighborSkt = exprManager.getOrCreateSkeleton(neighbor);
                        var hasConflict = neighborSkt.checkSizeConflict(sourceSizeInfo);

                        if (hasConflict) {
                            var direct = forward ? "forward" : "backward";
                            Logging.debug("ConstPropagator",
                                    String.format("Found Size Conflict when propagating (%s) from %s -> %s",
                                            direct, borderNode, neighbor));

                            sizeConflictNodes.add(neighbor);

                            neighborSkt.updateSizeSource(sourceSizeInfo);
                            sourceToPropagatedNodes.get(source).add(neighbor);
                        } else {
                            // mark as the new Border node
                            neighborSkt.updateSizeSource(sourceSizeInfo);
                            newBorderNodes.add(neighbor);
                            sourceToPropagatedNodes.get(source).add(neighbor);
                        }
                    }
                }

                // After all old border nodes are processed, we need to update the new border nodes.
                if (!newBorderNodes.isEmpty()) {
                    sourceToBorderNodes.get(source).addAll(newBorderNodes);
                    hasNewBorderNode = true;
                }
            }
        }
    }
}
