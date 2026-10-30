package body Transport_Graph_Parse with SPARK_Mode is
   subtype U16 is Natural range 0 .. 65_535;

   function Header (Wire : Wire_Buffer; Kind : Character) return Boolean
   with Global => null,
     Post => Header'Result =
       (Wire (1) = Character'Pos ('S') and then
        Wire (2) = Character'Pos ('T') and then
        Wire (3) = Byte (Character'Pos (Kind)) and then
        Wire (4) = Character'Pos ('1'))
   is
   begin
      return Wire (1) = Character'Pos ('S') and then
        Wire (2) = Character'Pos ('T') and then
        Wire (3) = Byte (Character'Pos (Kind)) and then
        Wire (4) = Character'Pos ('1');
   end Header;

   procedure Read_U16
     (Wire : Wire_Buffer; Length : Wire_Length; Pos : in out Cursor;
      Value : out U16; Result : out Status)
   with Global => null, Always_Terminates,
     Pre => Pos <= Length + 1,
     Post => Pos <= Length + 1 and then
       (if Result = Ok then Pos = Pos'Old + 2 and then
          Value = Natural (Wire (Pos'Old)) * 256 +
            Natural (Wire (Pos'Old + 1))
        else Pos = Pos'Old and then Value = 0)
   is
   begin
      Value := 0;
      if Pos > Length or else Length - Pos < 1 then
         Result := Truncated;
         return;
      end if;
      Value := Natural (Wire (Pos)) * 256 + Natural (Wire (Pos + 1));
      Pos := Pos + 2;
      Result := Ok;
   end Read_U16;

   procedure Read_Node
     (Wire : Wire_Buffer; Length : Wire_Length; Pos : in out Cursor;
      G : in out Graph; Index : Node_Id; Result : out Status)
   with Global => null, Always_Terminates,
     Pre => Pos <= Length + 1,
     Post => Pos <= Length + 1 and then Pos >= Pos'Old
   is
      Control, Size, Child : U16;
   begin
      Read_U16 (Wire, Length, Pos, Control, Result);
      if Result /= Ok then
         return;
      end if;
      Read_U16 (Wire, Length, Pos, Size, Result);
      if Result /= Ok then
         return;
      end if;
      if Control / 256 not in 1 .. Last_Op or else
        Control mod 256 > Max_Arity or else Size > Max_Literal
      then
         Result := Invalid_Graph;
         return;
      end if;
      G.Nodes (Index).Tag := Byte (Control / 256);
      G.Nodes (Index).Degree := Control mod 256;
      for J in 1 .. G.Nodes (Index).Degree loop
         pragma Loop_Invariant (Pos <= Length + 1);
         pragma Loop_Invariant (Pos >= Pos'Loop_Entry);
         Read_U16 (Wire, Length, Pos, Child, Result);
         if Result /= Ok or else Child not in 1 .. Index - 1 then
            Result := Invalid_Graph;
            return;
         end if;
         G.Nodes (Index).Children (J) := Child;
      end loop;
      if Size > Length + 1 - Pos or else Size > Max_Source - G.Used then
         Result := Capacity_Exceeded;
         return;
      end if;
      G.Nodes (Index).First := G.Used + 1;
      G.Nodes (Index).Size := Size;
      for J in 1 .. Size loop
         G.Data (G.Used + J) := Wire (Pos + J - 1);
      end loop;
      G.Used := G.Used + Size;
      Pos := Pos + Size;
      Result := Ok;
   end Read_Node;

   procedure Read_Graph
     (Wire : Wire_Buffer; Length : Wire_Length;
      G : out Graph; Result : out Status)
   is
      Pos : Cursor := 5;
      Count, Root : U16;
   begin
      G := (others => <>);
      Result := Bad_Header;
      if Length < 8 or else not Header (Wire, 'G') then
         return;
      end if;
      Read_U16 (Wire, Length, Pos, Count, Result);
      if Result /= Ok then
         return;
      end if;
      Read_U16 (Wire, Length, Pos, Root, Result);
      if Result /= Ok or else Count not in Node_Id or else
        Root not in 1 .. Count
      then
         Result := Invalid_Graph;
         return;
      end if;
      G.Count := Count;
      G.Root := Root;
      for I in 1 .. G.Count loop
         pragma Loop_Invariant (Pos <= Length + 1);
         Read_Node (Wire, Length, Pos, G, I, Result);
         if Result /= Ok then
            return;
         end if;
      end loop;
      if Pos /= Length + 1 then
         Result := Trailing_Data;
      elsif not Well_Formed (G) then
         Result := Invalid_Graph;
      end if;
   end Read_Graph;

   procedure Read_Path
     (Wire : Wire_Buffer; Length : Wire_Length;
      Choices : out Path; Count : out Path_Length; Result : out Status)
   is
      Pos : Cursor := 5;
      Raw_Count : U16;
   begin
      Choices := [others => 1];
      Count := 0;
      Result := Bad_Header;
      if Length < 6 or else not Header (Wire, 'P') then
         return;
      end if;
      Read_U16 (Wire, Length, Pos, Raw_Count, Result);
      if Result /= Ok then
         return;
      end if;
      if Raw_Count > Max_Nodes or else Length /= Pos - 1 + Raw_Count then
         Result := Invalid_Graph;
         return;
      end if;
      for I in 1 .. Raw_Count loop
         if Natural (Wire (6 + I)) not in Child_Position then
            Result := Invalid_Graph;
            return;
         end if;
         Choices (I) := Natural (Wire (6 + I));
         pragma Loop_Invariant
           (for all J in 1 .. I => Choices (J) = Natural (Wire (6 + J)));
         pragma Loop_Invariant
           (for all J in I + 1 .. Max_Nodes => Choices (J) = 1);
      end loop;
      Count := Raw_Count;
      Result := Ok;
   end Read_Path;

   procedure Read_Map
     (Wire : Wire_Buffer; Length : Wire_Length; Expected : Node_Id;
      Map : out Node_Map; Result : out Status)
   is
      Pos : Cursor := 5;
      Count, Value : U16;
   begin
      Map := [others => 0];
      Result := Bad_Header;
      if Length < 6 or else not Header (Wire, 'M') then
         return;
      end if;
      Read_U16 (Wire, Length, Pos, Count, Result);
      if Result /= Ok or else Count /= Expected then
         Result := Invalid_Graph;
         return;
      end if;
      for I in 1 .. Expected loop
         pragma Loop_Invariant (Pos <= Length + 1);
         pragma Loop_Invariant (for all J in 1 .. I - 1 => Map (J) > 0);
         Read_U16 (Wire, Length, Pos, Value, Result);
         if Result /= Ok or else Value not in Node_Id then
            Result := Invalid_Graph;
            return;
         end if;
         Map (I) := Value;
      end loop;
      if Pos /= Length + 1 then
         Result := Trailing_Data;
      end if;
   end Read_Map;
end Transport_Graph_Parse;
