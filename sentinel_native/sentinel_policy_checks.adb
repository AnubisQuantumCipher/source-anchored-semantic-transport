with Ada.Text_IO;
with Sentinel_Policy_Fixtures;

procedure Sentinel_Policy_Checks is
begin
   Sentinel_Policy_Fixtures.Run;
   Ada.Text_IO.Put_Line ("SENTINEL_POLICY_CHECKS_PASS");
end Sentinel_Policy_Checks;
