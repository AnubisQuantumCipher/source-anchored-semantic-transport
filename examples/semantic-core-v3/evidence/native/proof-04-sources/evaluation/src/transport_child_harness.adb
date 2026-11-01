package body Transport_Child_Harness with SPARK_Mode is
   procedure Good_Step (Parent : Scalar; Child : out Scalar) is
   begin
      Child := Parent;
   end Good_Step;

   procedure Store_Parent
     (Value : Scalar; Parent : out Scalar; Attempts : in out Attempt_Count)
   with Global => null, Always_Terminates, Pre => Attempts < Attempt_Count'Last,
     Post => Parent = Value and Attempts = Attempts'Old + 1
   is
   begin
      Attempts := Attempts + 1;
      Parent := Value;
   end Store_Parent;

   procedure Bad_Step
     (Mode : Scenario; Parent : in out Scalar; Attempts : in out Attempt_Count)
   with Global => null, Always_Terminates,
     Pre => Mode in Write_And_Restore | Same_Value_Write and
       Attempts <= Attempt_Count'Last - 2,
     Post => Parent = Parent'Old and
       Attempts = Attempts'Old + Writes_Per_Step (Mode)
   is
      Saved : constant Scalar := Parent;
      Changed : constant Scalar := (if Parent = Scalar'Last then 0 else Parent + 1);
   begin
      if Mode = Write_And_Restore then
         Store_Parent (Changed, Parent, Attempts);
         pragma Assert (Parent = Changed and Parent /= Saved);
         Store_Parent (Saved, Parent, Attempts);
      else
         Store_Parent (Saved, Parent, Attempts);
      end if;
   end Bad_Step;

   procedure Run (Mode : Scenario; Steps : Step_Count;
                  Parent, Child : Scalar; Result : out Observation) is
   begin
      Result := (Before_Parent => Parent, After_Parent => Parent,
                 Before_Child => Child, After_Child => Child, others => <>);
      if Mode = Unavailable then
         return;
      end if;
      for I in 1 .. Steps loop
         if Mode = Good_Child then
            Good_Step (Parent, Result.After_Child);
         else
            Bad_Step (Mode, Result.After_Parent, Result.Attempts);
         end if;
         Result.Completed := I;
         pragma Loop_Invariant (Result.Completed = I);
         pragma Loop_Invariant (Result.Attempts = Writes_Per_Step (Mode) * I);
         pragma Loop_Invariant
           (Result.Before_Parent = Parent and Result.After_Parent = Parent and
            Result.Before_Child = Child and not Result.Complete);
         pragma Loop_Invariant
           (Result.After_Child = (if Mode = Good_Child then Parent else Child));
      end loop;
      Result.Complete := Steps > 0;
   end Run;
end Transport_Child_Harness;
