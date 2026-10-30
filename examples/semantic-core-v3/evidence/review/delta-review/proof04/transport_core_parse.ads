with Transport_Eval;
with Transport_Types; use Transport_Types;

package Transport_Core_Parse with SPARK_Mode is
   --  STC3 fixed-width frame; source anchors and package binding are outside this parser.
   procedure Read
     (Wire : Wire_Buffer; Length : Wire_Length; T : out Transport_Eval.Core_Tree;
      M : out Transport_Eval.Finite_Model; Result : out Status)
   with Global => null, Always_Terminates,
     Post => (if Result = Ok then Transport_Eval.Well_Formed (T, M)
              else T.Count = 0 and M.Symbol_Count = 0);
end Transport_Core_Parse;
