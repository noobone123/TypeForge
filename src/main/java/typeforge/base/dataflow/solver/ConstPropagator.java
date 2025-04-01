package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.expression.NMAE;
import typeforge.utils.Global;

import java.io.File;

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

    InterSolver interSolver = null;

    public ConstPropagator(InterSolver interSolver) {
        this.interSolver = interSolver;
    }

    public void run() {
        propagateArgConst();
    }

    private void propagateArgConst() {
        var intraSolverMap = interSolver.intraSolverMap;
        var graphManager = interSolver.graphManager;

        var mallocCs = interSolver.mallocCs;
        var callocCs = interSolver.callocCs;

        for (var cs: callocCs) {
            if (cs.caller.getName().equals("ck_calloc")) {
                var arg1 = cs.arguments.get(0);
                var arg2 = cs.arguments.get(1);
                var receiver = cs.receiver;
                var arg1Facts = intraSolverMap.get(cs.caller).getDataFlowFacts(arg1);
                for (var arg1Fact: arg1Facts) {
                    graphManager.dumpPartialTFG(arg1Fact, 5, new File(Global.outputDirectory));
                }
            }
        }
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
