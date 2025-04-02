package typeforge.base.dataflow.solver;

import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.node.CallSite;
import typeforge.utils.Logging;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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

    enum AllocType {
        MALLOC,
        CALLOC
    }

    enum ConstType {
        MALLOC_SIZE,
        CALLOC_NITEMS,
        CALLOC_SIZE,
    }

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

    public ConstPropagator(InterSolver interSolver) {
        this.interSolver = interSolver;
    }

    public void run() {
        propagateConstArgs();
    }

    private void propagateConstArgs() {
        var intraSolverMap = interSolver.intraSolverMap;
        var graphManager = interSolver.graphManager;
        var exprManager = interSolver.exprManager;

        var wrapperCSSet = new HashSet<CallSite>();

        // Process malloc call sites
        processMallocCallSites(wrapperCSSet);

        // Process calloc call sites
        processCallocCallSites(wrapperCSSet);
    }

    private void processMallocCallSites(Set<CallSite> wrapperCSSet) {
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
        }
    }

    private void processCallocCallSites(Set<CallSite> wrapperCSSet) {
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
                    if (graphManager.hasDataFlowPath(from, to)) {
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


    private void updateReceivers(Set<CallSite> wrapperCallSites, Set<CallSite> wrapperCSSet, int type) {
    }

    // TODO:
    //  1. Constructing CallSite when building CallGraph, there should be a Map<CallSite, Callee> and a Map<Callee, Set<CallSite>>
    //  2. Reversing constructing the CallSite-Chain (Max-depth: 4? Because wrapper function is not that deep)
    //  3. For each chain, start from the nearest CallSite, check:
    //      1. If CallSite Args can not flow to the malloc(1) or calloc(2)'s corresponding arguments, return.
    //      2. If there are No ConstArg, but arguments can flow to the malloc(1) or calloc(2)'s corresponding arguments, goto the next CallSite and check.
    //      3. If there are ConstArg and can flow to the malloc(1) or calloc(2)'s corresponding arguments,
    //          check if the malloc(1) or calloc(2)'s return value can flow to the current callSite's receiver.
    //          If so, mark current callSite's receiver as composite and set the size, return.
    //      We will not handle Partial ConstArg, because it's very very rare.
    //  4. Build Map<Callee, Set<ReturnSize>> from the marked CallSites, if there are multiple sizes, mark it as EvilNode and mark RETURN edges from them as EvilEdges. (Actually TFG should be split)

    // TODO:
    //  1. If a variable is set to different size (with memset) with the same function, it must be a union, mark it as EvilNode and mark all edges to them as EvilEdges.
    //  2. For those Skeletons with size, we propagate them along the TFG, propagate should be 多点扩散法：
    //      即：假设图中有 n 个这样的节点，每一轮我们都将节点的信息，沿着dataflow边传播到它的邻居（函数的所有？）节点（是否按照函数粒度进行每次传播），然后我们检查这些新传播到的邻居节点的信息是否存在冲突，如果不存在，那么
    //      我们就把他们视作一个整体节点（邻居），然后继续传播。如果存在冲突，那么这个新的邻居节点就不应该被加入已有的整体节点，且该新节点和整体节点相连的所有的边都应该被删除。
    //  后续的每个子图的 type-hint propagation 是否也能够采用类似的思路？ 用于处理来自每个Source之间的类型传播，只不过此时的 check 的 conflict 变成了 field conflict

    // TODO: Implement me.
    private boolean hasPathFromAllocPtrToReceiver(NMAE allocPtr, NMAE receiver) {
        return false;
    }
}
