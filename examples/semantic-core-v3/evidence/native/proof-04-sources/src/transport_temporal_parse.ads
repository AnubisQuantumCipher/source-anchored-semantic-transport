with Transport_Temporal; use Transport_Temporal;
with Transport_Types; use Transport_Types;
with Transport_Temporal_Format;

package Transport_Temporal_Parse with SPARK_Mode is
   procedure Read_Model
     (Wire : Wire_Buffer; Length : Wire_Length;
      Item : out Model; Result : out Status)
   with Global => null, Always_Terminates,
     Post => ((Result = Ok) = Transport_Temporal_Format.Frame_Valid (Wire, Length)) and then
       (if Result = Ok then Transport_Temporal_Format.Represents (Wire, Length, Item)
        else Item = Model'(others => <>));
end Transport_Temporal_Parse;
