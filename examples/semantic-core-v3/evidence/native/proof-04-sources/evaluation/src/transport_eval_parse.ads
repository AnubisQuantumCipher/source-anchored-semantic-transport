with Transport_Eval;
with Transport_Child_Harness;
with Transport_Types; use Transport_Types;

package Transport_Eval_Parse with SPARK_Mode is
   procedure Read
     (Wire : Wire_Buffer; Length : Wire_Length; T : out Transport_Eval.Tree;
      Mode : out Transport_Child_Harness.Scenario;
      Steps : out Transport_Child_Harness.Step_Count;
      Parent, Child : out Transport_Child_Harness.Scalar; Result : out Status)
   with Global => null, Always_Terminates,
     Post => (if Result = Ok then Transport_Eval.Well_Formed (T)
              else T.Count = 0 and Steps = 0 and Parent = 0 and Child = 0);
end Transport_Eval_Parse;
