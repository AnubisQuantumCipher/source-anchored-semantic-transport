with Transport_Eval;

package Transport_Child_Harness with SPARK_Mode is
   subtype Scalar is Natural range 0 .. 255;
   subtype Step_Count is Natural range 0 .. 64;
   subtype Attempt_Count is Natural range 0 .. 128;
   type Scenario is (Unavailable, Good_Child, Write_And_Restore, Same_Value_Write);
   type Observation is record
      Before_Parent, After_Parent, Before_Child, After_Child : Scalar := 0;
      Completed : Step_Count := 0;
      Attempts : Attempt_Count := 0;
      Complete : Boolean := False;
   end record;

   procedure Good_Step (Parent : Scalar; Child : out Scalar)
   with Global => null, Depends => (Child => Parent), Always_Terminates,
     Post => Child = Parent;

   function Writes_Per_Step (Mode : Scenario) return Natural is
     (case Mode is when Unavailable | Good_Child => 0,
                   when Write_And_Restore => 2, when Same_Value_Write => 1)
   with Global => null;

   procedure Run (Mode : Scenario; Steps : Step_Count;
                  Parent, Child : Scalar; Result : out Observation)
   with Global => null, Always_Terminates,
     Post => Result.Before_Parent = Parent and Result.After_Parent = Parent and
       Result.Before_Child = Child and
       Result.Completed = (if Mode = Unavailable then 0 else Steps) and
       Result.Attempts = Writes_Per_Step (Mode) * Result.Completed and
       Result.Complete = (Mode /= Unavailable and Steps > 0) and
       Result.After_Child =
         (if Mode = Good_Child and Steps > 0 then Parent else Child);

   function Fact (Item : Observation) return Transport_Eval.Fact_Truth is
     (if Item.Attempts > 0 then Transport_Eval.Known_True
      elsif Item.Complete then Transport_Eval.Known_False else Transport_Eval.Unresolved)
   with Global => null;
end Transport_Child_Harness;
