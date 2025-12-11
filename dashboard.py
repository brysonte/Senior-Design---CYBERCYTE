import streamlit as st
import pandas as pd
import altair as alt
from datetime import timedelta, datetime

# Set page config
st.set_page_config(page_title="Autonomous Home Defense System", layout="wide")

# Helper functions
@st.cache_data
def load_data():
    data = pd.read_csv("security_events.csv", parse_dates=["DATE", "timestamp"])    
    data['DATE'] = pd.to_datetime(data['DATE'])
    return data

def create_metric_chart(df, column, color, chart_type, height=150, time_frame='Daily'):
    chart_data = df[[column]].copy()
    if time_frame == 'Quarterly':
        chart_data.index = chart_data.index.strftime('%Y Q%q ')
    if chart_type == 'Bar':
        st.bar_chart(chart_data, y=column, height=height)
    if chart_type == 'Area':
        st.area_chart(chart_data, y=column, height=height)

def calculate_delta(df, column):
    if len(df) < 2:
        return 0, 0
    current_value = df[column].iloc[-1]
    previous_value = df[column].iloc[-2]
    delta = current_value - previous_value
    delta_percent = (delta / previous_value) * 100 if previous_value != 0 else 0
    return delta, delta_percent

def format_with_commas(number):
    return f"{number:,}"

def display_metric(col, title, value, df, column, color, time_frame):
    with col:
        with st.container(border=True):
            delta, delta_percent = calculate_delta(df, column)
            delta_str = f"{delta:+,.0f} ({delta_percent:+.2f}%)"
            st.metric(title, format_with_commas(value), delta=delta_str)
            create_metric_chart(df, column, color, time_frame=time_frame, chart_type=chart_selection)

# Load data
df = load_data()

# Sidebar filters
with st.sidebar:
    st.title("Autonomous Home Defense System")
    st.header("⚙️ Settings")
    
    max_date = df['DATE'].max().date()
    default_start_date = max_date - timedelta(days=30)
    default_end_date = max_date
    start_date = st.date_input("Start date", default_start_date, min_value=df['DATE'].min().date(), max_value=max_date)
    end_date = st.date_input("End date", default_end_date, min_value=df['DATE'].min().date(), max_value=max_date)

    chart_selection = st.selectbox("Select a chart type", ("Bar", "Area"))

# Filter data based on date selection
filtered_df = df[(df['DATE'] >= pd.to_datetime(start_date)) & (df['DATE'] <= pd.to_datetime(end_date))]

# --- EVENTS OVER TIME ---
st.subheader("Events Over Time")
events_over_time = (
    filtered_df.groupby(filtered_df["timestamp"].dt.date)
    .size()
    .reset_index(name="count")
    .rename(columns={"timestamp": "date"})
)
line_chart = alt.Chart(events_over_time).mark_area(color="#29b5e8").encode(
    x="date:T",
    y="count:Q"
)
st.altair_chart(line_chart, use_container_width=True)

# --- EVENT TYPES BREAKDOWN ---
st.subheader("Event Types Breakdown")
event_breakdown = (
    filtered_df["event_type"]
    .value_counts()
    .reset_index()
    .rename(columns={"index": "event_type", "event_type": "count"})
)
bar_chart = alt.Chart(event_breakdown).mark_bar().encode(
    x="event_type:N",
    y="count:Q",
    color="event_type:N"
)
st.altair_chart(bar_chart, use_container_width=True)

# --- LIVE INCIDENT TABLE ---
st.subheader("Recent Incidents")
st.dataframe(
    filtered_df.sort_values("timestamp", ascending=False).head(20),
    use_container_width=True
)

# import streamlit as st
# import pandas as pd
# from datetime import timedelta, datetime

# # Set page config
# st.set_page_config(page_title="Autonomous Home Defense System", layout="wide")

# # Helper functions
# @st.cache_data
# def load_data():
#     data = pd.read_csv("security_events.csv", parse_dates=["timestamp"])    
#     data['DATE'] = pd.to_datetime(data['DATE'])
#     return data

# def custom_quarter(date):
#     month = date.month
#     year = date.year
#     if month in [2, 3, 4]:
#         return pd.Period(year=year, quarter=1, freq='Q')
#     elif month in [5, 6, 7]:
#         return pd.Period(year=year, quarter=2, freq='Q')
#     elif month in [8, 9, 10]:
#         return pd.Period(year=year, quarter=3, freq='Q')
#     else:  # month in [11, 12, 1]
#         return pd.Period(year=year if month != 1 else year-1, quarter=4, freq='Q')

# # def aggregate_data(df, freq):
# #     if freq == 'Q':
# #         df = df.copy()
# #         df['CUSTOM_Q'] = df['DATE'].apply(custom_quarter)
# #         df_agg = df.groupby('CUSTOM_Q').agg({
# #             'VIEWS': 'sum',
# #             'WATCH_HOURS': 'sum',
# #             'NET_SUBSCRIBERS': 'sum',
# #             'LIKES': 'sum',
# #             'COMMENTS': 'sum',
# #             'SHARES': 'sum',
# #         })
# #         return df_agg
# #     else:
# #         return df.resample(freq, on='DATE').agg({
# #             'VIEWS': 'sum',
# #             'WATCH_HOURS': 'sum',
# #             'NET_SUBSCRIBERS': 'sum',
# #             'LIKES': 'sum',
# #             'COMMENTS': 'sum',
# #             'SHARES': 'sum',
# #         })

# # def get_weekly_data(df):
# #     return aggregate_data(df, 'W-MON')

# # def get_monthly_data(df):
# #     return aggregate_data(df, 'M')

# # def get_quarterly_data(df):
# #     return aggregate_data(df, 'Q')

# # def format_with_commas(number):
# #     return f"{number:,}"

# def create_metric_chart(df, column, color, chart_type, height=150, time_frame='Daily'):
#     chart_data = df[[column]].copy()
#     if time_frame == 'Quarterly':
#         chart_data.index = chart_data.index.strftime('%Y Q%q ')
#     if chart_type=='Bar':
#         st.bar_chart(chart_data, y=column, color=color, height=height)
#     if chart_type=='Area':
#         st.area_chart(chart_data, y=column, color=color, height=height)

# def is_period_complete(date, freq):
#     today = datetime.now()
#     if freq == 'D':
#         return date.date() < today.date()
#     elif freq == 'W':
#         return date + timedelta(days=6) < today
#     elif freq == 'M':
#         next_month = date.replace(day=28) + timedelta(days=4)
#         return next_month.replace(day=1) <= today
#     elif freq == 'Q':
#         current_quarter = custom_quarter(today)
#         return date < current_quarter

# def calculate_delta(df, column):
#     if len(df) < 2:
#         return 0, 0
#     current_value = df[column].iloc[-1]
#     previous_value = df[column].iloc[-2]
#     delta = current_value - previous_value
#     delta_percent = (delta / previous_value) * 100 if previous_value != 0 else 0
#     return delta, delta_percent

# def display_metric(col, title, value, df, column, color, time_frame):
#     with col:
#         with st.container(border=True):
#             delta, delta_percent = calculate_delta(df, column)
#             delta_str = f"{delta:+,.0f} ({delta_percent:+.2f}%)"
#             st.metric(title, format_with_commas(value), delta=delta_str)
#             create_metric_chart(df, column, color, time_frame=time_frame, chart_type=chart_selection)
            
#             last_period = df.index[-1]
#             freq = {'Daily': 'D', 'Weekly': 'W', 'Monthly': 'M', 'Quarterly': 'Q'}[time_frame]
#             if not is_period_complete(last_period, freq):
#                 st.caption(f"Note: The last {time_frame.lower()[:-2] if time_frame != 'Daily' else 'day'} is incomplete.")

# # Load data
# df = load_data()

# # Set up input widgets
# st.logo(image="images/streamlit-logo-primary-colormark-lighttext.png", 
#         icon_image="images/streamlit-mark-color.png")

# with st.sidebar:
#     st.title("Autonomous Home Defense System")
#     st.header("⚙️ Settings")
    
#     max_date = df['DATE'].max().date()
#     default_start_date = max_date - timedelta(days=365)  # Show a year by default
#     default_end_date = max_date
#     start_date = st.date_input("Start date", default_start_date, min_value=df['DATE'].min().date(), max_value=max_date)
#     end_date = st.date_input("End date", default_end_date, min_value=df['DATE'].min().date(), max_value=max_date)
#     time_frame = st.selectbox("Select time frame",
#                               ("Daily", "Weekly", "Monthly", "Quarterly"),
#     )
#     chart_selection = st.selectbox("Select a chart type",
#                                    ("Bar", "Area"))

# # # Prepare data based on selected time frame
# # if time_frame == 'Daily':
# #     df_display = df.set_index('DATE')
# # elif time_frame == 'Weekly':
# #     df_display = get_weekly_data(df)
# # elif time_frame == 'Monthly':
# #     df_display = get_monthly_data(df)
# # elif time_frame == 'Quarterly':
# #     df_display = get_quarterly_data(df)

# st.subheader("Events Over Time")
# events_over_time = (
#     filtered_df.groupby(filtered_df["timestamp"].dt.date)
#     .size()
#     .reset_index(name="count")
# )
# line_chart = alt.Chart(events_over_time).mark_area().encode(
#     x="timestamp:T",
#     y="count:Q"
# )
# st.altair_chart(line_chart, use_container_width=True)

# st.subheader("Event Types Breakdown")
# event_breakdown = (
#     filtered_df["event_type"]
#     .value_counts()
#     .reset_index()
#     .rename(columns={"index": "event_type", "event_type": "count"})
# )
# bar_chart = alt.Chart(event_breakdown).mark_bar().encode(
#     x="event_type:N",
#     y="count:Q",
#     color="event_type:N"
# )
# st.altair_chart(bar_chart, use_container_width=True)

# # --- LIVE INCIDENT TABLE ---
# st.subheader("Recent Incidents")
# st.dataframe(
#     filtered_df.sort_values("timestamp", ascending=False).head(20),
#     use_container_width=True
# )
