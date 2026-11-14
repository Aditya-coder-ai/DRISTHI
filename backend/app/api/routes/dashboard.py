"""Dashboard Analytics endpoints."""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from backend.app.api.deps import get_analytics_service
from backend.app.schemas.dashboard import (
    DashboardStatsResponse,
    TimelineResponse,
    ServiceActivityResponse,
)
from backend.app.services.analytics_service import AnalyticsService

router = APIRouter()


@router.get("/dashboard/stats", response_model=DashboardStatsResponse, summary="Live aggregated statistics for the dashboard")
def get_stats(analytics: AnalyticsService = Depends(get_analytics_service)):
    """Computes real, database-derived summary metrics across all deception assets."""
    return analytics.get_dashboard_stats()


@router.get("/dashboard/timeline", response_model=TimelineResponse, summary="Attack activity timeline")
def get_timeline(
    hours: int = Query(24, ge=1, le=168, description="Historical window in hours"),
    analytics: AnalyticsService = Depends(get_analytics_service),
):
    """Returns time-bucketed event volume with critical and high severity breakdowns."""
    return analytics.get_timeline(hours=hours)


@router.get("/dashboard/services", response_model=ServiceActivityResponse, summary="Activity breakdown by deception service")
def get_services(analytics: AnalyticsService = Depends(get_analytics_service)):
    """Returns telemetry volume, unique attackers, and active sessions per deception honeypot."""
    return analytics.get_services_activity()

