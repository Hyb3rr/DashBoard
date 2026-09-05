"""Static canonical market catalog for the Global Market Opportunity foundation."""

from __future__ import annotations

from typing import Final


# Membership is intentionally a reviewed literal, not inferred from pycountry.
PRIMARY_UN_MEMBERS: Final[tuple[tuple[str, str, str], ...]] = (
    ('AD', 'Andorra', 'AND'), ('AE', 'United Arab Emirates', 'ARE'), ('AF', 'Afghanistan', 'AFG'),
    ('AG', 'Antigua and Barbuda', 'ATG'), ('AL', 'Albania', 'ALB'), ('AM', 'Armenia', 'ARM'),
    ('AO', 'Angola', 'AGO'), ('AR', 'Argentina', 'ARG'), ('AT', 'Austria', 'AUT'), ('AU', 'Australia', 'AUS'),
    ('AZ', 'Azerbaijan', 'AZE'), ('BA', 'Bosnia and Herzegovina', 'BIH'), ('BB', 'Barbados', 'BRB'),
    ('BD', 'Bangladesh', 'BGD'), ('BE', 'Belgium', 'BEL'), ('BF', 'Burkina Faso', 'BFA'), ('BG', 'Bulgaria', 'BGR'),
    ('BH', 'Bahrain', 'BHR'), ('BI', 'Burundi', 'BDI'), ('BJ', 'Benin', 'BEN'), ('BN', 'Brunei Darussalam', 'BRN'),
    ('BO', 'Bolivia, Plurinational State of', 'BOL'), ('BR', 'Brazil', 'BRA'), ('BS', 'Bahamas', 'BHS'),
    ('BT', 'Bhutan', 'BTN'), ('BW', 'Botswana', 'BWA'), ('BY', 'Belarus', 'BLR'), ('BZ', 'Belize', 'BLZ'),
    ('CA', 'Canada', 'CAN'), ('CD', 'Congo, The Democratic Republic of the', 'COD'),
    ('CF', 'Central African Republic', 'CAF'), ('CG', 'Congo', 'COG'), ('CH', 'Switzerland', 'CHE'),
    ('CI', "Côte d'Ivoire", 'CIV'), ('CL', 'Chile', 'CHL'), ('CM', 'Cameroon', 'CMR'), ('CN', 'China', 'CHN'),
    ('CO', 'Colombia', 'COL'), ('CR', 'Costa Rica', 'CRI'), ('CU', 'Cuba', 'CUB'), ('CV', 'Cabo Verde', 'CPV'),
    ('CY', 'Cyprus', 'CYP'), ('CZ', 'Czechia', 'CZE'), ('DE', 'Germany', 'DEU'), ('DJ', 'Djibouti', 'DJI'),
    ('DK', 'Denmark', 'DNK'), ('DM', 'Dominica', 'DMA'), ('DO', 'Dominican Republic', 'DOM'), ('DZ', 'Algeria', 'DZA'),
    ('EC', 'Ecuador', 'ECU'), ('EE', 'Estonia', 'EST'), ('EG', 'Egypt', 'EGY'), ('ER', 'Eritrea', 'ERI'),
    ('ES', 'Spain', 'ESP'), ('ET', 'Ethiopia', 'ETH'), ('FI', 'Finland', 'FIN'), ('FJ', 'Fiji', 'FJI'),
    ('FM', 'Micronesia, Federated States of', 'FSM'), ('FR', 'France', 'FRA'), ('GA', 'Gabon', 'GAB'),
    ('GB', 'United Kingdom', 'GBR'), ('GD', 'Grenada', 'GRD'), ('GE', 'Georgia', 'GEO'), ('GH', 'Ghana', 'GHA'),
    ('GM', 'Gambia', 'GMB'), ('GN', 'Guinea', 'GIN'), ('GQ', 'Equatorial Guinea', 'GNQ'), ('GR', 'Greece', 'GRC'),
    ('GT', 'Guatemala', 'GTM'), ('GW', 'Guinea-Bissau', 'GNB'), ('GY', 'Guyana', 'GUY'), ('HN', 'Honduras', 'HND'),
    ('HR', 'Croatia', 'HRV'), ('HT', 'Haiti', 'HTI'), ('HU', 'Hungary', 'HUN'), ('ID', 'Indonesia', 'IDN'),
    ('IE', 'Ireland', 'IRL'), ('IL', 'Israel', 'ISR'), ('IN', 'India', 'IND'), ('IQ', 'Iraq', 'IRQ'),
    ('IR', 'Iran, Islamic Republic of', 'IRN'), ('IS', 'Iceland', 'ISL'), ('IT', 'Italy', 'ITA'), ('JM', 'Jamaica', 'JAM'),
    ('JO', 'Jordan', 'JOR'), ('JP', 'Japan', 'JPN'), ('KE', 'Kenya', 'KEN'), ('KG', 'Kyrgyzstan', 'KGZ'),
    ('KH', 'Cambodia', 'KHM'), ('KI', 'Kiribati', 'KIR'), ('KM', 'Comoros', 'COM'), ('KN', 'Saint Kitts and Nevis', 'KNA'),
    ('KP', "Korea, Democratic People's Republic of", 'PRK'), ('KR', 'Korea, Republic of', 'KOR'), ('KW', 'Kuwait', 'KWT'),
    ('KZ', 'Kazakhstan', 'KAZ'), ('LA', "Lao People's Democratic Republic", 'LAO'), ('LB', 'Lebanon', 'LBN'),
    ('LC', 'Saint Lucia', 'LCA'), ('LI', 'Liechtenstein', 'LIE'), ('LK', 'Sri Lanka', 'LKA'), ('LR', 'Liberia', 'LBR'),
    ('LS', 'Lesotho', 'LSO'), ('LT', 'Lithuania', 'LTU'), ('LU', 'Luxembourg', 'LUX'), ('LV', 'Latvia', 'LVA'),
    ('LY', 'Libya', 'LBY'), ('MA', 'Morocco', 'MAR'), ('MC', 'Monaco', 'MCO'), ('MD', 'Moldova, Republic of', 'MDA'),
    ('ME', 'Montenegro', 'MNE'), ('MG', 'Madagascar', 'MDG'), ('MH', 'Marshall Islands', 'MHL'), ('MK', 'North Macedonia', 'MKD'),
    ('ML', 'Mali', 'MLI'), ('MM', 'Myanmar', 'MMR'), ('MN', 'Mongolia', 'MNG'), ('MR', 'Mauritania', 'MRT'),
    ('MT', 'Malta', 'MLT'), ('MU', 'Mauritius', 'MUS'), ('MV', 'Maldives', 'MDV'), ('MW', 'Malawi', 'MWI'),
    ('MX', 'Mexico', 'MEX'), ('MY', 'Malaysia', 'MYS'), ('MZ', 'Mozambique', 'MOZ'), ('NA', 'Namibia', 'NAM'),
    ('NE', 'Niger', 'NER'), ('NG', 'Nigeria', 'NGA'), ('NI', 'Nicaragua', 'NIC'), ('NL', 'Netherlands', 'NLD'),
    ('NO', 'Norway', 'NOR'), ('NP', 'Nepal', 'NPL'), ('NR', 'Nauru', 'NRU'), ('NZ', 'New Zealand', 'NZL'),
    ('OM', 'Oman', 'OMN'), ('PA', 'Panama', 'PAN'), ('PE', 'Peru', 'PER'), ('PG', 'Papua New Guinea', 'PNG'),
    ('PH', 'Philippines', 'PHL'), ('PK', 'Pakistan', 'PAK'), ('PL', 'Poland', 'POL'), ('PT', 'Portugal', 'PRT'),
    ('PW', 'Palau', 'PLW'), ('PY', 'Paraguay', 'PRY'), ('QA', 'Qatar', 'QAT'), ('RO', 'Romania', 'ROU'),
    ('RS', 'Serbia', 'SRB'), ('RU', 'Russian Federation', 'RUS'), ('RW', 'Rwanda', 'RWA'), ('SA', 'Saudi Arabia', 'SAU'),
    ('SB', 'Solomon Islands', 'SLB'), ('SC', 'Seychelles', 'SYC'), ('SD', 'Sudan', 'SDN'), ('SE', 'Sweden', 'SWE'),
    ('SG', 'Singapore', 'SGP'), ('SI', 'Slovenia', 'SVN'), ('SK', 'Slovakia', 'SVK'), ('SL', 'Sierra Leone', 'SLE'),
    ('SM', 'San Marino', 'SMR'), ('SN', 'Senegal', 'SEN'), ('SO', 'Somalia', 'SOM'), ('SR', 'Suriname', 'SUR'),
    ('SS', 'South Sudan', 'SSD'), ('ST', 'Sao Tome and Principe', 'STP'), ('SV', 'El Salvador', 'SLV'),
    ('SY', 'Syrian Arab Republic', 'SYR'), ('SZ', 'Eswatini', 'SWZ'), ('TD', 'Chad', 'TCD'), ('TG', 'Togo', 'TGO'),
    ('TH', 'Thailand', 'THA'), ('TJ', 'Tajikistan', 'TJK'), ('TL', 'Timor-Leste', 'TLS'), ('TM', 'Turkmenistan', 'TKM'),
    ('TN', 'Tunisia', 'TUN'), ('TO', 'Tonga', 'TON'), ('TR', 'Türkiye', 'TUR'), ('TT', 'Trinidad and Tobago', 'TTO'),
    ('TV', 'Tuvalu', 'TUV'), ('TZ', 'Tanzania, United Republic of', 'TZA'), ('UA', 'Ukraine', 'UKR'), ('UG', 'Uganda', 'UGA'),
    ('US', 'United States', 'USA'), ('UY', 'Uruguay', 'URY'), ('UZ', 'Uzbekistan', 'UZB'), ('VC', 'Saint Vincent and the Grenadines', 'VCT'),
    ('VE', 'Venezuela, Bolivarian Republic of', 'VEN'), ('VN', 'Viet Nam', 'VNM'), ('VU', 'Vanuatu', 'VUT'),
    ('WS', 'Samoa', 'WSM'), ('YE', 'Yemen', 'YEM'), ('ZA', 'South Africa', 'ZAF'), ('ZM', 'Zambia', 'ZMB'), ('ZW', 'Zimbabwe', 'ZWE'),
)

NON_PRIMARY_ECONOMIES: Final[tuple[tuple[str, str, str | None], ...]] = (
    ('AS', 'American Samoa', 'ASM'), ('AW', 'Aruba', 'ABW'), ('BM', 'Bermuda', 'BMU'), ('CW', 'Curaçao', 'CUW'),
    ('FO', 'Faroe Islands', 'FRO'), ('GI', 'Gibraltar', 'GIB'), ('GL', 'Greenland', 'GRL'), ('GU', 'Guam', 'GUM'),
    ('HK', 'Hong Kong', 'HKG'), ('IM', 'Isle of Man', 'IMN'), ('KY', 'Cayman Islands', 'CYM'), ('MF', 'Saint Martin (French part)', 'MAF'),
    ('MO', 'Macao', 'MAC'), ('MP', 'Northern Mariana Islands', 'MNP'), ('MS', 'Montserrat', 'MSR'), ('NC', 'New Caledonia', 'NCL'),
    ('PF', 'French Polynesia', 'PYF'), ('PR', 'Puerto Rico', 'PRI'), ('PS', 'Palestine, State of', 'PSE'), ('SX', 'Sint Maarten (Dutch part)', 'SXM'),
    ('TC', 'Turks and Caicos Islands', 'TCA'), ('VG', 'Virgin Islands, British', 'VGB'), ('VI', 'Virgin Islands, U.S.', 'VIR'),
    ('XK', 'Kosovo', None),
)


def catalog_rows() -> list[dict[str, object]]:
    """Return a fresh, deterministic 217-row bootstrap payload."""
    primary = [
        {"country_code": code, "country_name": name, "iso3_code": iso3,
         "un_member": True, "primary_market": True, "active": True}
        for code, name, iso3 in PRIMARY_UN_MEMBERS
    ]
    extras = [
        {"country_code": code, "country_name": name, "iso3_code": iso3,
         "un_member": False, "primary_market": False, "active": True}
        for code, name, iso3 in NON_PRIMARY_ECONOMIES
    ]
    return primary + extras


if len(PRIMARY_UN_MEMBERS) != 193:  # pragma: no cover - import invariant
    raise RuntimeError("canonical UN member catalog must contain exactly 193 entries")
if len(NON_PRIMARY_ECONOMIES) != 24:  # pragma: no cover - import invariant
    raise RuntimeError("non-primary economy catalog must contain exactly 24 entries")
