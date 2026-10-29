# Source-Anchored Semantic Transport lexicon.md

All metadata below are unverified declarations.
Original bytes are retained. Binary media are retained, not understood.
Anchors prove references to selected bytes only; they do not prove a reading.

<pre>
SOURCES
id: REQUIREMENT
label: REQUIREMENT
media_type: text/plain; charset=utf-8
provenance: Synthetic public fixture; no current execution authority.

id: EVIDENCE
label: EVIDENCE
media_type: text/plain; charset=utf-8
provenance: Synthetic public fixture; no current execution authority.

id: HISTORY
label: HISTORY
media_type: text/plain; charset=utf-8
provenance: Synthetic public fixture; no current execution authority.

INTERPRETATIONS
anchors: &#91;{&quot;sha256&quot;:&quot;b7b43a38005473ff105ed8378cdd3df2598398ec155454a111578b6acd696e6d&quot;,&quot;source&quot;:&quot;REQUIREMENT&quot;,&quot;span&quot;:&#91;0,120&#93;}&#93;
id: I&#95;REQUIREMENT
label: REQUIREMENT
provenance: Bound evaluation deterministic fixture, not external evidence.
status: proposed
text: Explicit synthetic reading; entailment and report authenticity remain unproved.

anchors: &#91;{&quot;sha256&quot;:&quot;930a72959b6c5f2087ae40809642390da4c50cdb190e07ae7ecf97c41c0cccf3&quot;,&quot;source&quot;:&quot;EVIDENCE&quot;,&quot;span&quot;:&#91;0,146&#93;}&#93;
id: I&#95;EVIDENCE
label: EVIDENCE
provenance: Bound evaluation deterministic fixture, not external evidence.
status: proposed
text: Explicit synthetic reading; entailment and report authenticity remain unproved.

anchors: &#91;{&quot;sha256&quot;:&quot;2d2926804df66722f1948321e1575333644d378b620c1c0adc09edd489d30ac1&quot;,&quot;source&quot;:&quot;HISTORY&quot;,&quot;span&quot;:&#91;0,183&#93;}&#93;
id: I&#95;HISTORY
label: HISTORY
provenance: Bound evaluation deterministic fixture, not external evidence.
status: proposed
text: Explicit synthetic reading; entailment and report authenticity remain unproved.

UNCERTAINTIES
affects: &#91;&quot;I&#95;REQUIREMENT&quot;,&quot;I&#95;EVIDENCE&quot;,&quot;I&#95;HISTORY&quot;&#93;
anchors: &#91;{&quot;sha256&quot;:&quot;2d2926804df66722f1948321e1575333644d378b620c1c0adc09edd489d30ac1&quot;,&quot;source&quot;:&quot;HISTORY&quot;,&quot;span&quot;:&#91;0,183&#93;}&#93;
id: REPORT&#95;AUTHENTICITY
text: Reports and correction precedence remain unauthenticated.

RELATIONS
anchors: &#91;{&quot;sha256&quot;:&quot;2d2926804df66722f1948321e1575333644d378b620c1c0adc09edd489d30ac1&quot;,&quot;source&quot;:&quot;HISTORY&quot;,&quot;span&quot;:&#91;0,183&#93;}&#93;
from: I&#95;HISTORY
kind: qualifies
note: History is retained; this relation does not select a true report.
to: I&#95;EVIDENCE

</pre>

Interpretation supplied: YES
Coverage is a byte-reference report; no semantic completeness is claimed.

## Fixed definitions

- Σ: Documentary source group only; not an arithmetic sum, universal quantifier or completeness claim.
- I: Ordered declared interpretation IDs and statuses; none means no interpretation was supplied.
- U: Ordered uncertainty IDs; none means no uncertainty record was supplied, not absence of uncertainty.
- R: Ordered declared relations, written first kind second; no causality, execution or authority is implied.
- anchor: Half-open offsets [begin,end) in exact original bytes with SHA-256 of the selected bytes; a reference only, not entailment.
- M: Typed meaning units with indexed operator trees, fixed dictionary identities and declared context dependencies; interpretation and adequacy remain unproved.
- supports: Declared support from the first record to the second; no entailment or truth is verified.
- contradicts: Declared conflict between the first record and the second; no inconsistency is proved.
- qualifies: The first record declares a qualification on the second; no scope or adequacy is verified.
- derived_from: The first record is declared derived from the second; no derivation is checked.
- supersedes: The first record is declared to replace the second in this reading; no authority is granted.

## Typed meaning units

Types and source occurrences are checked. Interpretation, completeness and context adequacy remain UNPROVEN.
Historical approvals are evidence only. No unit grants current execution authority.

### U_REQUIREMENT / instruction

Source: REQUIREMENT; interpretation: I_REQUIREMENT
Declared context units: 

| Symbol | Exact source literal |
|---|---|
| S0 | Inez |
| S1 | atlas |
| S2 | Omar |
| S3 | deliver |

| Operator | Argument types | Result | Exact definition |
|---|---|---|---|
| all | var, term, prop | prop | Bind the first variable universally over the declared domain in the body. |
| and | prop, prop | prop | Both propositions hold in the declared reading. |
| attribution | term, prop | prop | First operand is the source of the claim; no narrator endorsement. |
| belief | term, prop | prop | First operand believes the proposition; not asserted as fact. |
| cause | prop, prop | prop | Declared causal claim from first operand to second; not verified causality. |
| if | prop, prop | prop | First operand is a sufficient condition for the second in the declared reading. |
| may | prop | prop | Declared permission; no obligation to perform it. |
| must | prop | prop | Declared obligation; no satisfaction or authority verdict. |
| not | prop | prop | Negate the enclosed proposition. |
| only&#95;after | prop, prop | prop | First operand may occur only after the second is complete; no occurrence is promised or authorized. |
| parallel | prop, prop | prop | Tracks proceed in parallel; no interaction or completion rule implied. |
| pred | text, term-or-var... | prop | Source predicate applied to ordered explicit terms or bound variables; interpretation is declared. |
| quantity | text, text | term | Exact amount spelling and unit spelling; no evaluation or conversion. |
| requires | prop, prop | prop | Second operand is necessary for the first; does not authorize execution. |
| sequence | prop, prop | prop | First operand precedes the second; no causation implied. |
| should | prop | prop | Declared recommendation, distinct from an obligation. |
| some | var, term, prop | prop | Bind the first variable existentially over the declared domain in the body. |
| uncertain | text, prop | prop | Retain the exact uncertainty qualification on this proposition. |
| unless | prop, prop | prop | Second operand is an exception to the first; no converse obligation implied. |
| within | prop, term | prop | Declared inclusive deadline quantity for this proposition; origin must be explicit or ambiguous. |

<pre>
n0 = term&#40;S0&#41;\u000an1 = term&#40;S1&#41;\u000an2 = term&#40;S2&#41;\u000an3 = text&#40;S3&#41;\u000an4 = pred&#40;n3, n0, n1, n2&#41;\u000an5 = not&#40;n4&#41;\u000an6 = must&#40;n5&#41;\u000aroot n6
</pre>

<pre>{&quot;context&quot;:&#91;&#93;,&quot;dictionaries&quot;:&#91;{&quot;content&quot;:{&quot;entries&quot;:{&quot;all&quot;:{&quot;args&quot;:&#91;&quot;var&quot;,&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Bind the first variable universally over the declared domain in the body.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;and&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Both propositions hold in the declared reading.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;attribution&quot;:{&quot;args&quot;:&#91;&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand is the source of the claim; no narrator endorsement.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;belief&quot;:{&quot;args&quot;:&#91;&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand believes the proposition; not asserted as fact.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;cause&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared causal claim from first operand to second; not verified causality.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;if&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand is a sufficient condition for the second in the declared reading.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;may&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared permission; no obligation to perform it.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;must&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared obligation; no satisfaction or authority verdict.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;not&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Negate the enclosed proposition.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;only&#95;after&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand may occur only after the second is complete; no occurrence is promised or authorized.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;parallel&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Tracks proceed in parallel; no interaction or completion rule implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;pred&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;term-or-var...&quot;&#93;,&quot;definition&quot;:&quot;Source predicate applied to ordered explicit terms or bound variables; interpretation is declared.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;quantity&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;text&quot;&#93;,&quot;definition&quot;:&quot;Exact amount spelling and unit spelling; no evaluation or conversion.&quot;,&quot;result&quot;:&quot;term&quot;},&quot;requires&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Second operand is necessary for the first; does not authorize execution.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;sequence&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand precedes the second; no causation implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;should&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared recommendation, distinct from an obligation.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;some&quot;:{&quot;args&quot;:&#91;&quot;var&quot;,&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Bind the first variable existentially over the declared domain in the body.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;uncertain&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Retain the exact uncertainty qualification on this proposition.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;unless&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Second operand is an exception to the first; no converse obligation implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;within&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;term&quot;&#93;,&quot;definition&quot;:&quot;Declared inclusive deadline quantity for this proposition; origin must be explicit or ambiguous.&quot;,&quot;result&quot;:&quot;prop&quot;}},&quot;id&quot;:&quot;transport-operators&quot;,&quot;role&quot;:&quot;operators&quot;,&quot;schema&quot;:&quot;transport/dictionary/1&quot;,&quot;version&quot;:&quot;1&quot;},&quot;id&quot;:&quot;transport-operators&quot;,&quot;role&quot;:&quot;operators&quot;,&quot;sha256&quot;:&quot;021441fbc5ec70acca1818b44cbf4af91500743aa5523bc406700f7241eefa07&quot;,&quot;version&quot;:&quot;1&quot;},{&quot;content&quot;:{&quot;entries&quot;:{&quot;S0&quot;:&quot;Inez&quot;,&quot;S1&quot;:&quot;atlas&quot;,&quot;S2&quot;:&quot;Omar&quot;,&quot;S3&quot;:&quot;deliver&quot;},&quot;id&quot;:&quot;document-symbols&quot;,&quot;role&quot;:&quot;symbols&quot;,&quot;schema&quot;:&quot;transport/dictionary/1&quot;,&quot;version&quot;:&quot;1&quot;},&quot;id&quot;:&quot;document-symbols&quot;,&quot;role&quot;:&quot;symbols&quot;,&quot;sha256&quot;:&quot;5d73f83ae2cb07bfaba6fd0a36a9882dd066662cfb0ad741298628bce4cf1644&quot;,&quot;version&quot;:&quot;1&quot;}&#93;,&quot;grammar&quot;:&quot;transport/meaning/1&quot;,&quot;id&quot;:&quot;U&#95;REQUIREMENT&quot;,&quot;interpretation&quot;:&quot;I&#95;REQUIREMENT&quot;,&quot;kind&quot;:&quot;instruction&quot;,&quot;meaning&quot;:{&quot;ambiguities&quot;:&#91;&#93;,&quot;nodes&quot;:&#91;{&quot;op&quot;:&quot;term&quot;,&quot;span&quot;:&#91;0,4&#93;,&quot;symbol&quot;:&quot;S0&quot;},{&quot;op&quot;:&quot;term&quot;,&quot;span&quot;:&#91;26,31&#93;,&quot;symbol&quot;:&quot;S1&quot;},{&quot;op&quot;:&quot;term&quot;,&quot;span&quot;:&#91;35,39&#93;,&quot;symbol&quot;:&quot;S2&quot;},{&quot;op&quot;:&quot;text&quot;,&quot;span&quot;:&#91;14,21&#93;,&quot;symbol&quot;:&quot;S3&quot;},{&quot;args&quot;:&#91;3,0,1,2&#93;,&quot;cue&quot;:&#91;14,21&#93;,&quot;op&quot;:&quot;pred&quot;},{&quot;args&quot;:&#91;4&#93;,&quot;cue&quot;:&#91;10,13&#93;,&quot;op&quot;:&quot;not&quot;},{&quot;args&quot;:&#91;5&#93;,&quot;cue&quot;:&#91;5,9&#93;,&quot;op&quot;:&quot;must&quot;}&#93;,&quot;root&quot;:6,&quot;schema&quot;:&quot;transport/meaning/1&quot;},&quot;source&quot;:&quot;REQUIREMENT&quot;}</pre>

### U_EVIDENCE / source_claim

Source: EVIDENCE; interpretation: I_EVIDENCE
Declared context units: 

| Symbol | Exact source literal |
|---|---|
| S0 | The dispatch record reports that Inez delivered the atlas to Omar.\u000aThis is an attributed documentary report, not authenticated delivery evidence.\u000a |

| Operator | Argument types | Result | Exact definition |
|---|---|---|---|
| all | var, term, prop | prop | Bind the first variable universally over the declared domain in the body. |
| and | prop, prop | prop | Both propositions hold in the declared reading. |
| attribution | term, prop | prop | First operand is the source of the claim; no narrator endorsement. |
| belief | term, prop | prop | First operand believes the proposition; not asserted as fact. |
| cause | prop, prop | prop | Declared causal claim from first operand to second; not verified causality. |
| if | prop, prop | prop | First operand is a sufficient condition for the second in the declared reading. |
| may | prop | prop | Declared permission; no obligation to perform it. |
| must | prop | prop | Declared obligation; no satisfaction or authority verdict. |
| not | prop | prop | Negate the enclosed proposition. |
| only&#95;after | prop, prop | prop | First operand may occur only after the second is complete; no occurrence is promised or authorized. |
| parallel | prop, prop | prop | Tracks proceed in parallel; no interaction or completion rule implied. |
| pred | text, term-or-var... | prop | Source predicate applied to ordered explicit terms or bound variables; interpretation is declared. |
| quantity | text, text | term | Exact amount spelling and unit spelling; no evaluation or conversion. |
| requires | prop, prop | prop | Second operand is necessary for the first; does not authorize execution. |
| sequence | prop, prop | prop | First operand precedes the second; no causation implied. |
| should | prop | prop | Declared recommendation, distinct from an obligation. |
| some | var, term, prop | prop | Bind the first variable existentially over the declared domain in the body. |
| uncertain | text, prop | prop | Retain the exact uncertainty qualification on this proposition. |
| unless | prop, prop | prop | Second operand is an exception to the first; no converse obligation implied. |
| within | prop, term | prop | Declared inclusive deadline quantity for this proposition; origin must be explicit or ambiguous. |

<pre>
n0 = atom&#40;S0&#41;\u000aroot n0
</pre>

<pre>{&quot;context&quot;:&#91;&#93;,&quot;dictionaries&quot;:&#91;{&quot;content&quot;:{&quot;entries&quot;:{&quot;all&quot;:{&quot;args&quot;:&#91;&quot;var&quot;,&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Bind the first variable universally over the declared domain in the body.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;and&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Both propositions hold in the declared reading.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;attribution&quot;:{&quot;args&quot;:&#91;&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand is the source of the claim; no narrator endorsement.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;belief&quot;:{&quot;args&quot;:&#91;&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand believes the proposition; not asserted as fact.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;cause&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared causal claim from first operand to second; not verified causality.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;if&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand is a sufficient condition for the second in the declared reading.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;may&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared permission; no obligation to perform it.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;must&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared obligation; no satisfaction or authority verdict.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;not&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Negate the enclosed proposition.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;only&#95;after&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand may occur only after the second is complete; no occurrence is promised or authorized.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;parallel&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Tracks proceed in parallel; no interaction or completion rule implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;pred&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;term-or-var...&quot;&#93;,&quot;definition&quot;:&quot;Source predicate applied to ordered explicit terms or bound variables; interpretation is declared.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;quantity&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;text&quot;&#93;,&quot;definition&quot;:&quot;Exact amount spelling and unit spelling; no evaluation or conversion.&quot;,&quot;result&quot;:&quot;term&quot;},&quot;requires&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Second operand is necessary for the first; does not authorize execution.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;sequence&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand precedes the second; no causation implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;should&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared recommendation, distinct from an obligation.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;some&quot;:{&quot;args&quot;:&#91;&quot;var&quot;,&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Bind the first variable existentially over the declared domain in the body.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;uncertain&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Retain the exact uncertainty qualification on this proposition.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;unless&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Second operand is an exception to the first; no converse obligation implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;within&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;term&quot;&#93;,&quot;definition&quot;:&quot;Declared inclusive deadline quantity for this proposition; origin must be explicit or ambiguous.&quot;,&quot;result&quot;:&quot;prop&quot;}},&quot;id&quot;:&quot;transport-operators&quot;,&quot;role&quot;:&quot;operators&quot;,&quot;schema&quot;:&quot;transport/dictionary/1&quot;,&quot;version&quot;:&quot;1&quot;},&quot;id&quot;:&quot;transport-operators&quot;,&quot;role&quot;:&quot;operators&quot;,&quot;sha256&quot;:&quot;021441fbc5ec70acca1818b44cbf4af91500743aa5523bc406700f7241eefa07&quot;,&quot;version&quot;:&quot;1&quot;},{&quot;content&quot;:{&quot;entries&quot;:{&quot;S0&quot;:&quot;The dispatch record reports that Inez delivered the atlas to Omar.\nThis is an attributed documentary report, not authenticated delivery evidence.\n&quot;},&quot;id&quot;:&quot;document-symbols&quot;,&quot;role&quot;:&quot;symbols&quot;,&quot;schema&quot;:&quot;transport/dictionary/1&quot;,&quot;version&quot;:&quot;1&quot;},&quot;id&quot;:&quot;document-symbols&quot;,&quot;role&quot;:&quot;symbols&quot;,&quot;sha256&quot;:&quot;410a260858aef9fa2ad831fe6e509e4f49e02d850eca8107920230a03280b999&quot;,&quot;version&quot;:&quot;1&quot;}&#93;,&quot;grammar&quot;:&quot;transport/meaning/1&quot;,&quot;id&quot;:&quot;U&#95;EVIDENCE&quot;,&quot;interpretation&quot;:&quot;I&#95;EVIDENCE&quot;,&quot;kind&quot;:&quot;source&#95;claim&quot;,&quot;meaning&quot;:{&quot;ambiguities&quot;:&#91;&#93;,&quot;nodes&quot;:&#91;{&quot;op&quot;:&quot;atom&quot;,&quot;span&quot;:&#91;0,146&#93;,&quot;symbol&quot;:&quot;S0&quot;}&#93;,&quot;root&quot;:0,&quot;schema&quot;:&quot;transport/meaning/1&quot;},&quot;source&quot;:&quot;EVIDENCE&quot;}</pre>

### U_HISTORY / source_claim

Source: HISTORY; interpretation: I_HISTORY
Declared context units: 

| Symbol | Exact source literal |
|---|---|
| S0 | An earlier dispatch record denied that Inez delivered the atlas to Omar.\u000aA later correction reports delivery. Both reports remain preserved; precedence is not automatically resolved.\u000a |

| Operator | Argument types | Result | Exact definition |
|---|---|---|---|
| all | var, term, prop | prop | Bind the first variable universally over the declared domain in the body. |
| and | prop, prop | prop | Both propositions hold in the declared reading. |
| attribution | term, prop | prop | First operand is the source of the claim; no narrator endorsement. |
| belief | term, prop | prop | First operand believes the proposition; not asserted as fact. |
| cause | prop, prop | prop | Declared causal claim from first operand to second; not verified causality. |
| if | prop, prop | prop | First operand is a sufficient condition for the second in the declared reading. |
| may | prop | prop | Declared permission; no obligation to perform it. |
| must | prop | prop | Declared obligation; no satisfaction or authority verdict. |
| not | prop | prop | Negate the enclosed proposition. |
| only&#95;after | prop, prop | prop | First operand may occur only after the second is complete; no occurrence is promised or authorized. |
| parallel | prop, prop | prop | Tracks proceed in parallel; no interaction or completion rule implied. |
| pred | text, term-or-var... | prop | Source predicate applied to ordered explicit terms or bound variables; interpretation is declared. |
| quantity | text, text | term | Exact amount spelling and unit spelling; no evaluation or conversion. |
| requires | prop, prop | prop | Second operand is necessary for the first; does not authorize execution. |
| sequence | prop, prop | prop | First operand precedes the second; no causation implied. |
| should | prop | prop | Declared recommendation, distinct from an obligation. |
| some | var, term, prop | prop | Bind the first variable existentially over the declared domain in the body. |
| uncertain | text, prop | prop | Retain the exact uncertainty qualification on this proposition. |
| unless | prop, prop | prop | Second operand is an exception to the first; no converse obligation implied. |
| within | prop, term | prop | Declared inclusive deadline quantity for this proposition; origin must be explicit or ambiguous. |

<pre>
n0 = atom&#40;S0&#41;\u000aroot n0
</pre>

<pre>{&quot;context&quot;:&#91;&#93;,&quot;dictionaries&quot;:&#91;{&quot;content&quot;:{&quot;entries&quot;:{&quot;all&quot;:{&quot;args&quot;:&#91;&quot;var&quot;,&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Bind the first variable universally over the declared domain in the body.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;and&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Both propositions hold in the declared reading.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;attribution&quot;:{&quot;args&quot;:&#91;&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand is the source of the claim; no narrator endorsement.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;belief&quot;:{&quot;args&quot;:&#91;&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand believes the proposition; not asserted as fact.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;cause&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared causal claim from first operand to second; not verified causality.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;if&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand is a sufficient condition for the second in the declared reading.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;may&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared permission; no obligation to perform it.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;must&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared obligation; no satisfaction or authority verdict.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;not&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Negate the enclosed proposition.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;only&#95;after&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand may occur only after the second is complete; no occurrence is promised or authorized.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;parallel&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Tracks proceed in parallel; no interaction or completion rule implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;pred&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;term-or-var...&quot;&#93;,&quot;definition&quot;:&quot;Source predicate applied to ordered explicit terms or bound variables; interpretation is declared.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;quantity&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;text&quot;&#93;,&quot;definition&quot;:&quot;Exact amount spelling and unit spelling; no evaluation or conversion.&quot;,&quot;result&quot;:&quot;term&quot;},&quot;requires&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Second operand is necessary for the first; does not authorize execution.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;sequence&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;First operand precedes the second; no causation implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;should&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Declared recommendation, distinct from an obligation.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;some&quot;:{&quot;args&quot;:&#91;&quot;var&quot;,&quot;term&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Bind the first variable existentially over the declared domain in the body.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;uncertain&quot;:{&quot;args&quot;:&#91;&quot;text&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Retain the exact uncertainty qualification on this proposition.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;unless&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;prop&quot;&#93;,&quot;definition&quot;:&quot;Second operand is an exception to the first; no converse obligation implied.&quot;,&quot;result&quot;:&quot;prop&quot;},&quot;within&quot;:{&quot;args&quot;:&#91;&quot;prop&quot;,&quot;term&quot;&#93;,&quot;definition&quot;:&quot;Declared inclusive deadline quantity for this proposition; origin must be explicit or ambiguous.&quot;,&quot;result&quot;:&quot;prop&quot;}},&quot;id&quot;:&quot;transport-operators&quot;,&quot;role&quot;:&quot;operators&quot;,&quot;schema&quot;:&quot;transport/dictionary/1&quot;,&quot;version&quot;:&quot;1&quot;},&quot;id&quot;:&quot;transport-operators&quot;,&quot;role&quot;:&quot;operators&quot;,&quot;sha256&quot;:&quot;021441fbc5ec70acca1818b44cbf4af91500743aa5523bc406700f7241eefa07&quot;,&quot;version&quot;:&quot;1&quot;},{&quot;content&quot;:{&quot;entries&quot;:{&quot;S0&quot;:&quot;An earlier dispatch record denied that Inez delivered the atlas to Omar.\nA later correction reports delivery. Both reports remain preserved; precedence is not automatically resolved.\n&quot;},&quot;id&quot;:&quot;document-symbols&quot;,&quot;role&quot;:&quot;symbols&quot;,&quot;schema&quot;:&quot;transport/dictionary/1&quot;,&quot;version&quot;:&quot;1&quot;},&quot;id&quot;:&quot;document-symbols&quot;,&quot;role&quot;:&quot;symbols&quot;,&quot;sha256&quot;:&quot;3336b810074fce48dd85fc84de8bb8516c252605f115ec0dded903b5dc14c608&quot;,&quot;version&quot;:&quot;1&quot;}&#93;,&quot;grammar&quot;:&quot;transport/meaning/1&quot;,&quot;id&quot;:&quot;U&#95;HISTORY&quot;,&quot;interpretation&quot;:&quot;I&#95;HISTORY&quot;,&quot;kind&quot;:&quot;source&#95;claim&quot;,&quot;meaning&quot;:{&quot;ambiguities&quot;:&#91;&#93;,&quot;nodes&quot;:&#91;{&quot;op&quot;:&quot;atom&quot;,&quot;span&quot;:&#91;0,183&#93;,&quot;symbol&quot;:&quot;S0&quot;}&#93;,&quot;root&quot;:0,&quot;schema&quot;:&quot;transport/meaning/1&quot;},&quot;source&quot;:&quot;HISTORY&quot;}</pre>


## Decoder and boundary

Use the separately supplied Transport decoder and matching runtime; never execute archive content.
This ZIP has exactly manifest.json, codec.json, index.json, formula.txt, README.md.
README.md is this lexicon.md document; the separately returned lexicon bytes are identical.
STS1 binds bytes and declarations, not author identity, truth, confidentiality or authority.
No reference is fetched. Missing or incompatible external dependencies refuse before reconstruction.
External trusted runtime; hash-then-use does not isolate hostile concurrent same-user mutation.
