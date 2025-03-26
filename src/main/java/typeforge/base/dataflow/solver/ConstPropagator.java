package typeforge.base.dataflow.solver;

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
    
}
